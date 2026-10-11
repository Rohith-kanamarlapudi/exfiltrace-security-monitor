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
    assert a["verdict"] == "VERIFIED_TRANSFER" and a["severity"] == "CRITICAL"
    assert a["rule"] == "SENSITIVE_FILE_COPIED_TO_USB"
    text = " ".join(a["evidence"])
    assert "SHA-256" in text and "VID 0781" in text and str(env.dirs["monitored"]) in text
    assert "does not show who made the copy" in a["explanation"]
    assert a["file_event_ids"] and a["usb_event_ids"] and a["timestamp"]


def test_same_name_different_content_is_suspicious_not_verified(env):
    (env.dirs["monitored"] / "confidential.txt").write_text(SECRET)
    (env.dirs["usb"] / "confidential.txt").write_text("edited " + SECRET)
    [a] = env.record("CREATED", env.dirs["usb"] / "confidential.txt")[1]
    assert a["verdict"] == "SUSPICIOUS" and a["severity"] == "HIGH"
    assert "NOT a verified transfer" in a["explanation"]


def test_sensitive_file_on_usb_with_unknown_source_is_medium_suspicious(env):
    (env.dirs["usb"] / "passwords.txt").write_text("x")
    [a] = env.record("CREATED", env.dirs["usb"] / "passwords.txt")[1]
    assert a["verdict"] == "SUSPICIOUS" and a["severity"] == "MEDIUM"
    assert "origin is unknown" in a["explanation"]


def test_ordinary_file_on_usb_is_not_alerted(env):
    (env.dirs["usb"] / "holiday.jpg").write_text("x")
    assert env.record("CREATED", env.dirs["usb"] / "holiday.jpg")[1] == []


def test_non_sensitive_identical_copy_is_not_alerted(env):
    (env.dirs["monitored"] / "recipe.txt").write_text("pasta")
    (env.dirs["usb"] / "recipe.txt").write_text("pasta")
    assert env.record("CREATED", env.dirs["usb"] / "recipe.txt")[1] == []


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
