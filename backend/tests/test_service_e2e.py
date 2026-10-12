"""End to end: real watchdog observer + mocked USB insertion + detection + API."""
import shutil

from app.api import create_app
from app.service import MonitoringService
from tests.conftest import make_device, wait_for


def test_full_pipeline_copy_to_usb_is_verified(config, db, backend, dirs):
    svc = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    app = create_app(service=svc, autostart=False)
    client = app.test_client()
    svc.start()
    try:
        # A sensitive file exists in the monitored folder
        src = dirs["monitored"] / "confidential.txt"
        src.write_text("board minutes\n" * 100)

        # Insert a mocked USB stick whose "drive" is a temp folder
        backend.devices = [make_device(dirs["usb"], "STICK1")]
        svc.usb.poll_once()
        usb_events = client.get("/api/usb/events").get_json()["data"]
        assert usb_events[0]["event_type"] == "INSERTED" and usb_events[0]["vendor_id"] == "0781"
        assert str(dirs["usb"]) in client.get("/api/status").get_json()["data"]["file_monitor"]["removable_watches"]
        # Connecting alone is never a verified transfer (a weak LOW "coincident" alert may exist for the
        # source file's own creation event, which is expected).
        assert client.get("/api/alerts?verdict=VERIFIED_TRANSFER").get_json()["total"] == 0
        assert all(a["severity"] == "LOW" for a in client.get("/api/alerts").get_json()["data"])

        # "Copy" the file to the USB drive
        shutil.copy(src, dirs["usb"] / "confidential.txt")
        assert wait_for(lambda: client.get("/api/alerts?verdict=VERIFIED_TRANSFER").get_json()["total"] >= 1)
        alert = client.get("/api/alerts?verdict=VERIFIED_TRANSFER").get_json()["data"][0]
        assert alert["severity"] == "CRITICAL"
        ev = client.get("/api/files/events?removable=true").get_json()["data"]
        assert ev and ev[0]["usb_device_id"] == "STICK1"

        # Remove the stick: watch is dropped and a REMOVED event stored
        backend.devices = []
        svc.usb.poll_once()
        assert client.get("/api/usb/events?type=REMOVED").get_json()["total"] == 1
        assert str(dirs["usb"]) not in client.get("/api/status").get_json()["data"]["file_monitor"]["removable_watches"]
    finally:
        svc.stop()
    assert not svc.files.running and not svc.usb.running


def test_device_already_plugged_in_at_startup(config, db, backend, dirs):
    backend.devices = [make_device(dirs["usb"], "OLD")]
    svc = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    svc.start()
    try:
        [ev] = db.query_usb_events()[0]
        assert ev["details"]["preexisting"] is True
    finally:
        svc.stop()


def test_async_detection_worker_processes_events(config, db, backend, dirs):
    svc = MonitoringService(config, db=db, usb_backend=backend, async_detection=True)
    svc.start()
    try:
        backend.devices = [make_device(dirs["usb"], "S")]
        svc.usb.poll_once()
        (dirs["usb"] / "passwords.txt").write_text("hunter2")
        assert wait_for(lambda: db.alert_count() >= 1)
        assert svc.status()["detection"]["worker_alive"] is True
    finally:
        svc.stop()
    assert svc.status()["detection"]["worker_alive"] is False
