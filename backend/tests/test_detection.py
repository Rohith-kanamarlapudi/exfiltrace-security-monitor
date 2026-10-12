import pytest

from app.detection import DetectionEngine
from app.file_monitor import FileMonitor
from app.usb.monitor import UsbMonitor
from tests.conftest import make_device

SECRET = "Q3 salary table\n" * 50


@pytest.fixture
def env(config, db, backend, dirs):
    usb = UsbMonitor(backend)
    backend.devices = [make_device(dirs["usb"], "DEV1")]
    usb.poll_once()
    dev = usb.devices()[0]
    db.add_usb_event(event_type="INSERTED", device_id="DEV1", name=dev["name"], vendor_id="0781",
                     product_id="5567", serial_number="0001", mounts=dev["mounts"], details={})
    engine = DetectionEngine(config, db, usb)
    files = FileMonitor(config, db, volume_resolver=usb.volume_for)

    class Env:
        pass
    e = Env()
    e.config, e.db, e.usb, e.engine, e.files, e.dirs, e.backend = config, db, usb, engine, files, dirs, backend

    def record(event_type, path, dest=None):
        ev = files.handle(event_type, str(path), dest=dest and str(dest))
        assert ev, f"event not recorded for {path}"
        return ev, engine.on_file_event(ev)
    e.record = record
    return e


def test_usb_insertion_alone_creates_no_alert(env):
    assert env.db.alert_count() == 0


def test_verified_copy_when_hash_identical(env):
    (env.dirs["monitored"] / "confidential.txt").write_text(SECRET)
    (env.dirs["usb"] / "confidential.txt").write_text(SECRET)
    _, alerts = env.record("CREATED", env.dirs["usb"] / "confidential.txt")
    [a] = alerts
    assert a["verdict"] == "VERIFIED_TRANSFER" and a["severity"] == "MEDIUM"
    assert a["rule"] == "MONITORED_FILE_COPIED_TO_USB"
    text = " ".join(a["evidence"])
    assert "SHA-256" in text and "VID 0781" in text and str(env.dirs["monitored"]) in text
    assert "does not show who made the copy" in a["explanation"]
    assert a["file_event_ids"] and a["usb_event_ids"] and a["timestamp"]


def test_same_name_different_content_is_suspicious_not_verified(env):
    (env.dirs["monitored"] / "confidential.txt").write_text(SECRET)
    (env.dirs["usb"] / "confidential.txt").write_text("edited " + SECRET)
    [a] = env.record("CREATED", env.dirs["usb"] / "confidential.txt")[1]
    assert a["verdict"] == "SUSPICIOUS" and a["severity"] == "MEDIUM"
    assert "NOT a verified transfer" in a["explanation"]


def test_sensitive_file_on_usb_with_unknown_source_is_medium_suspicious(env):
    (env.dirs["usb"] / "passwords.txt").write_text("x")
    [a] = env.record("CREATED", env.dirs["usb"] / "passwords.txt")[1]
    assert a["verdict"] == "SUSPICIOUS" and a["severity"] == "MEDIUM"
    assert "origin is unknown" in a["explanation"]


def test_ordinary_file_on_usb_is_not_alerted(env):
    (env.dirs["usb"] / "holiday.jpg").write_text("x")
    assert env.record("CREATED", env.dirs["usb"] / "holiday.jpg")[1] == []


def test_non_sensitive_identical_copy_is_recorded(env):
    (env.dirs["monitored"] / "recipe.txt").write_text("pasta")
    (env.dirs["usb"] / "recipe.txt").write_text("pasta")
    [alert] = env.record("CREATED", env.dirs["usb"] / "recipe.txt")[1]
    assert alert['verdict'] == 'VERIFIED_TRANSFER' and alert['severity'] == 'MEDIUM'


def test_duplicate_events_do_not_duplicate_alerts(env):
    (env.dirs["monitored"] / "confidential.txt").write_text(SECRET)
    (env.dirs["usb"] / "confidential.txt").write_text(SECRET)
    ev, first = env.record("CREATED", env.dirs["usb"] / "confidential.txt")
    assert len(first) == 1 and env.engine.on_file_event(ev) == []
    assert env.db.alert_count() == 1


def test_bulk_copy_alert(env):
    for i in range(4):
        (env.dirs["usb"] / f"file{i}.dat").write_text(str(i))
        _, alerts = env.record("CREATED", env.dirs["usb"] / f"file{i}.dat")
    [a] = alerts
    assert a["rule"] == "BULK_COPY_TO_USB" and a["verdict"] == "SUSPICIOUS"
    assert len(a["file_event_ids"]) == 4


def test_archive_on_usb_alert(env):
    (env.dirs["usb"] / "backup.zip").write_bytes(b"PK")
    alerts = env.record("CREATED", env.dirs["usb"] / "backup.zip")[1]
    assert [a["rule"] for a in alerts] == ["ARCHIVE_ON_USB"]
    assert "unverified" in alerts[0]["explanation"]


def test_delete_after_copy_flags_possible_move(env):
    (env.dirs["usb"] / "confidential.txt").write_text("different bytes")
    env.record("CREATED", env.dirs["usb"] / "confidential.txt")
    src = env.dirs["monitored"] / "confidential.txt"
    alerts = env.record("DELETED", src)[1]
    moved = [a for a in alerts if a["rule"] == "SENSITIVE_FILE_MOVED_TO_USB"]
    assert moved and moved[0]["verdict"] == "SUSPICIOUS" and "unverified" in moved[0]["explanation"]


def test_sensitive_activity_while_usb_connected_is_low_and_says_no_transfer(env):
    (env.dirs["monitored"] / "confidential.txt").write_text("v1")
    [a] = env.record("MODIFIED", env.dirs["monitored"] / "confidential.txt")[1]
    assert a["rule"] == "SENSITIVE_ACTIVITY_DURING_USB" and a["severity"] == "LOW"
    assert "NOT evidence of a transfer" in a["explanation"]


def test_no_coincident_alert_without_usb(env):
    env.backend.devices = []
    env.usb.poll_once()
    (env.dirs["monitored"] / "confidential.txt").write_text("v1")
    assert env.record("MODIFIED", env.dirs["monitored"] / "confidential.txt")[1] == []


def test_detection_errors_are_contained(env, monkeypatch):
    monkeypatch.setattr(env.engine, "_removable_write", lambda *a: 1 / 0)
    (env.dirs["usb"] / "confidential.txt").write_text("x")
    assert env.record("CREATED", env.dirs["usb"] / "confidential.txt")[1] == []


def test_transfer_count_boundaries_and_repeated_events(env):
    for index, expected in enumerate(['MEDIUM', 'MEDIUM', 'MEDIUM', 'CRITICAL']):
        name = f'ordinary-{index}.txt'
        contents = f'file contents {index}'
        (env.dirs['monitored'] / name).write_text(contents)
        destination = env.dirs['usb'] / name; destination.write_text(contents)
        event, alerts = env.record('CREATED', destination)
        assert len(alerts) == 1 and alerts[0]['severity'] == expected
        assert env.engine.on_file_event(event) == []
    assert env.db.alert_count() == 4


@pytest.mark.parametrize('sizes, expected', [([5_000_000], ['MEDIUM']), ([5_000_001], ['CRITICAL']),
                                         ([2_500_000, 2_500_001], ['MEDIUM', 'CRITICAL'])])
def test_five_mb_size_boundary_and_aggregate_bytes(env, sizes, expected):
    for index, size in enumerate(sizes):
        source = env.dirs['monitored'] / f'data{index}.bin'
        destination = env.dirs['usb'] / source.name
        source.write_bytes(bytes([index]) * size); destination.write_bytes(source.read_bytes())
        _, alerts = env.record('CREATED', destination)
        assert len(alerts) == 1 and alerts[0]['severity'] == expected[index]


def test_renamed_destination_detected_by_hash_and_outside_sources_excluded(env):
    (env.dirs['monitored'] / 'original.txt').write_text('unique matching content')
    target = env.dirs['usb'] / 'renamed.txt'; target.write_text('unique matching content')
    _, alerts = env.record('CREATED', target)
    assert alerts[0]['verdict'] == 'VERIFIED_TRANSFER'
    outside = env.dirs['root'] / 'not-monitored.txt'; outside.write_text('outside')
    target = env.dirs['usb'] / outside.name; target.write_text('outside')
    assert env.record('CREATED', target)[1] == []


def test_transfer_window_persists_across_restart_and_is_device_scoped(env):
    from app.db import Database
    for index in range(3):
        name = f'ordinary{index}.txt'
        (env.dirs['monitored'] / name).write_text(str(index))
        (env.dirs['usb'] / name).write_text(str(index))
        env.record('CREATED', env.dirs['usb'] / name)
    env.engine = DetectionEngine(env.config, Database(env.db.path), env.usb)
    (env.dirs['monitored'] / 'fourth.txt').write_text('fourth')
    (env.dirs['usb'] / 'fourth.txt').write_text('fourth')
    assert env.record('CREATED', env.dirs['usb'] / 'fourth.txt')[1][0]['severity'] == 'CRITICAL'
    with env.db.connect() as conn:
        conn.execute("UPDATE usb_transfers SET timestamp='2000-01-01T00:00:00Z'")
    (env.dirs['monitored'] / 'next-window.txt').write_text('next-window')
    (env.dirs['usb'] / 'next-window.txt').write_text('next-window')
    assert env.record('CREATED', env.dirs['usb'] / 'next-window.txt')[1][0]['severity'] == 'MEDIUM'
    other = env.dirs['root'] / 'other-usb'; other.mkdir()
    env.backend.devices.append(make_device(other, 'OTHER'))
    env.usb.poll_once()
    (other / 'fourth.txt').write_text('fourth')
    assert env.record('CREATED', other / 'fourth.txt')[1][0]['severity'] == 'MEDIUM'


def test_hash_size_limit_never_fabricates_verified_transfer(env):
    env.config.data['detection']['max_hash_bytes'] = 2
    (env.dirs['monitored'] / 'ordinary.bin').write_bytes(b'large')
    (env.dirs['usb'] / 'ordinary.bin').write_bytes(b'large')
    alerts = env.record('CREATED', env.dirs['usb'] / 'ordinary.bin')[1]
    assert alerts and all(a['verdict'] == 'SUSPICIOUS' for a in alerts)


def test_changed_file_versions_accumulate_bytes_without_inflating_file_count(env):
    env.config.data['detection']['usb_transfer_size_limit_bytes'] = 5
    source = env.dirs['monitored'] / 'ordinary.txt'
    destination = env.dirs['usb'] / 'ordinary.txt'
    source.write_text('abc'); destination.write_text('abc')
    assert env.record('CREATED', destination)[1][0]['severity'] == 'MEDIUM'
    source.write_text('xyz'); destination.write_text('xyz')
    # Independent MODIFY after the create suppression window.
    env.files.window = 0
    _, alerts = env.record('MODIFIED', destination)
    assert len(alerts) == 1 and alerts[0]['severity'] == 'CRITICAL'
    assert '1 distinct files, 6 bytes' in ' '.join(alerts[0]['evidence'])


def test_new_device_connection_resets_transfer_count(env):
    for index in range(3):
        name = f'connection-file{index}.txt'
        (env.dirs['monitored'] / name).write_text(str(index))
        (env.dirs['usb'] / name).write_text(str(index))
        env.record('CREATED', env.dirs['usb'] / name)
    env.db.add_usb_event(event_type='INSERTED', device_id='DEV1', name='Reconnected', mounts=[str(env.dirs['usb'])])
    (env.dirs['monitored'] / 'connection-new.txt').write_text('new')
    (env.dirs['usb'] / 'connection-new.txt').write_text('new')
    assert env.record('CREATED', env.dirs['usb'] / 'connection-new.txt')[1][0]['severity'] == 'MEDIUM'
