import os
import shutil

from app.db import Database
from app.file_monitor import FileClassifier, FileMonitor
from tests.conftest import wait_for


def _events(db, **kw):
    return db.query_file_events(**kw)[0]


def _start(config, db, **kw):
    mon = FileMonitor(config, db, **kw)
    mon.start()
    return mon


def test_detects_create_modify_delete_rename(config, db, dirs):
    mon = _start(config, db)
    try:
        target = dirs["monitored"] / "notes.txt"
        target.write_text("hello")
        assert wait_for(lambda: any(e["event_type"] == "CREATED" for e in _events(db)))
        created = [e for e in _events(db) if e["event_type"] == "CREATED"][0]
        assert created["path"] == str(target) and created["file_name"] == "notes.txt"
        assert created["timestamp"]
        assert wait_for(lambda: [e for e in _events(db) if e["event_type"] == "CREATED"][0]["size_bytes"] == 5)

        import time; time.sleep(0.5)               # leave the dedupe window
        with open(target, "a") as fh:
            fh.write(" world")
        assert wait_for(lambda: any(e["event_type"] == "MODIFIED" for e in _events(db)))

        renamed_to = dirs["monitored"] / "notes_renamed.txt"
        os.rename(target, renamed_to)
        assert wait_for(lambda: any(e["event_type"] == "RENAMED" for e in _events(db)))
        ren = [e for e in _events(db) if e["event_type"] == "RENAMED"][0]
        assert ren["path"] == str(target) and ren["dest_path"] == str(renamed_to)

        os.remove(renamed_to)
        assert wait_for(lambda: any(e["event_type"] == "DELETED" for e in _events(db)))
    finally:
        mon.stop()


def test_sensitive_rules_by_name_extension_and_directory(config):
    c = FileClassifier(config)
    assert c.classify("/x/confidential.txt") == (True, "File name contains 'confidential'")
    assert c.classify("/x/vault.kdbx")[0] is True
    assert c.classify("/x/HR/report.docx")[0] is True
    assert c.classify("/x/holiday.jpg") == (False, None)


def test_exclusions(config, db, dirs):
    mon = FileMonitor(config, db)
    assert mon.handle("CREATED", str(dirs["monitored"] / "scratch.tmp")) is None
    assert mon.handle("CREATED", str(dirs["monitored"] / "~$report.docx")) is None
    assert mon.handle("CREATED", str(dirs["monitored"] / ".git" / "config")) is None
    assert mon.handle("CREATED", str(dirs["monitored"] / "ok.txt")) is not None
    assert db.query_file_events()[1] == 1


def test_duplicate_events_are_dropped_then_allowed_after_window(config, db, dirs):
    import time
    mon = FileMonitor(config, db)
    p = str(dirs["monitored"] / "a.txt")
    assert mon.handle("MODIFIED", p) is not None
    assert mon.handle("MODIFIED", p) is None            # inside window
    time.sleep(0.4)
    assert mon.handle("MODIFIED", p) is not None        # window expired


def test_modify_right_after_create_is_not_a_separate_event(config, db, dirs):
    mon = FileMonitor(config, db)
    p = str(dirs["monitored"] / "b.txt")
    assert mon.handle("CREATED", p) is not None
    assert mon.handle("MODIFIED", p) is None


def test_events_persist_across_restart(config, dirs):
    db1 = Database(config.database_path)
    FileMonitor(config, db1).handle("CREATED", str(dirs["monitored"] / "confidential.txt"))
    db2 = Database(config.database_path)                # new connection = "restart"
    rows, total = db2.query_file_events()
    assert total == 1 and rows[0]["sensitive"] is True and rows[0]["risk"] == "MEDIUM"


def test_missing_directory_does_not_crash_and_is_reported(config, db, dirs):
    config.data["monitored_directories"] = [str(dirs["root"] / "nope"), str(dirs["monitored"])]
    mon = _start(config, db)
    try:
        watches = {w["path"]: w for w in mon.watches()}
        assert watches[str(dirs["root"] / "nope")]["active"] is False
        assert "does not exist" in watches[str(dirs["root"] / "nope")]["error"]
        assert watches[str(dirs["monitored"])]["active"] is True
        assert mon.errors
    finally:
        mon.stop()


def test_callback_failure_is_contained(config, db, dirs):
    def boom(_):
        raise RuntimeError("callback failed")
    mon = FileMonitor(config, db, on_event=boom)
    assert mon.handle("CREATED", str(dirs["monitored"] / "c.txt")) is not None
    assert any("callback failed" in e for e in mon.errors)


def test_start_stop_is_clean_and_idempotent(config, db):
    mon = _start(config, db)
    assert mon.running
    mon.stop()
    mon.stop()
    assert not mon.running and mon.watches() == []


def test_events_on_removable_volume_are_flagged(config, db, dirs):
    dev = {"device_id": "d1", "name": "Stick"}
    mon = FileMonitor(config, db, volume_resolver=lambda p: (str(dirs["usb"]), dev) if str(p).startswith(str(dirs["usb"])) else None)
    ev = mon.handle("CREATED", str(dirs["usb"] / "confidential.txt"))
    assert ev["on_removable"] is True and ev["usb_device_id"] == "d1" and ev["risk"] == "HIGH"


def test_size_is_corrected_when_modify_follows_create(config, db, dirs):
    mon = FileMonitor(config, db)
    p = dirs["monitored"] / "growing.bin"
    p.write_bytes(b"")
    ev = mon.handle("CREATED", str(p))
    assert ev["size_bytes"] == 0
    p.write_bytes(b"x" * 321)
    assert mon.handle("MODIFIED", str(p)) is None              # not a separate event...
    assert db.query_file_events()[0][0]["size_bytes"] == 321   # ...but the CREATED row now has the real size
