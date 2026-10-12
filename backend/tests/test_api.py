import pytest

from app.api import create_app
from app.service import MonitoringService
from tests.conftest import make_device


@pytest.fixture
def client(config, db, backend, dirs):
    svc = MonitoringService(config, db=db, usb_backend=backend, async_detection=False)
    app = create_app(service=svc, autostart=False)
    app.config["TESTING"] = True
    c = app.test_client()
    c.svc, c.db, c.dirs = svc, db, dirs
    return c


def seed(db):
    db.add_file_event(event_type="CREATED", path="/d/confidential.txt", file_name="confidential.txt", sensitive=1,
                      sensitivity_reason="r", risk="MEDIUM", details={})
    db.add_file_event(event_type="DELETED", path="/d/photo.jpg", file_name="photo.jpg", risk="LOW", details={})
    db.add_file_event(event_type="CREATED", path="/usb/passwords.txt", file_name="passwords.txt", sensitive=1,
                      on_removable=1, volume="/usb", usb_device_id="D", risk="HIGH", details={})
    db.add_usb_event(event_type="INSERTED", device_id="D", name="Stick", vendor_id="0781", product_id="5567",
                     serial_number="1", mounts=["/usb"], details={})
    db.add_alert(rule="R", severity="HIGH", verdict="SUSPICIOUS", title="t", explanation="e", evidence=["x"],
                 file_event_ids=[1], usb_event_ids=[1], dedupe_key="k1")
    db.add_alert(rule="R2", severity="CRITICAL", verdict="VERIFIED_TRANSFER", title="t2", explanation="e",
                 evidence=[], file_event_ids=[], usb_event_ids=[], dedupe_key="k2")


def test_health_and_status_shape(client):
    assert client.get("/api/health").get_json()["status"] == "ok"
    d = client.get("/api/status").get_json()["data"]
    assert {"running", "file_monitor", "usb_monitor", "detection", "database"} <= set(d)
    assert d["usb_monitor"]["backend"] == "fake" and d["running"] is False


def test_file_events_listing_and_schema(client):
    seed(client.db)
    body = client.get("/api/files/events").get_json()
    assert body["total"] == 3 and body["source"] == "live"
    ev = body["data"][0]
    for key in ("id", "timestamp", "event_type", "path", "dest_path", "file_name", "size_bytes", "sensitive",
                "sensitivity_reason", "on_removable", "volume", "usb_device_id", "risk", "details"):
        assert key in ev


def test_file_event_filters(client):
    seed(client.db)
    get = lambda q: client.get("/api/files/events?" + q).get_json()  # noqa: E731
    assert get("type=DELETED")["total"] == 1
    assert get("type=deleted")["total"] == 1
    assert get("sensitive=true")["total"] == 2
    assert get("removable=true")["data"][0]["file_name"] == "passwords.txt"
    assert get("search=photo")["total"] == 1
    assert len(get("limit=1")["data"]) == 1 and get("limit=1")["total"] == 3


def test_invalid_parameters_return_400(client):
    assert client.get("/api/files/events?type=BOGUS").status_code == 400
    assert client.get("/api/files/events?limit=abc").status_code == 400
    assert client.get("/api/files/events?sensitive=maybe").status_code == 400
    assert "error" in client.get("/api/alerts?severity=NOPE").get_json()


def test_usb_alert_and_sensitive_endpoints(client):
    seed(client.db)
    assert client.get("/api/usb/events").get_json()["data"][0]["mounts"] == ["/usb"]
    assert client.get("/api/usb/events?type=REMOVED").get_json()["total"] == 0
    alerts = client.get("/api/alerts").get_json()
    assert alerts["total"] == 2 and isinstance(alerts["data"][0]["evidence"], list)
    assert client.get("/api/alerts?verdict=VERIFIED_TRANSFER").get_json()["total"] == 1
    assert client.get("/api/alerts?severity=high").get_json()["total"] == 1
    assert client.get("/api/files/stats").get_json()["data"]["sensitive_events"] == 2
    assert client.get("/api/files/sensitive").get_json()["total"] == 2


def test_unknown_route_and_method_return_json_errors(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["error"]
    assert client.delete("/api/status").status_code == 405


def test_usb_devices_endpoint_reflects_polled_devices(client, dirs):
    client.svc.usb.backend.devices = [make_device(dirs["usb"], "DEV")]
    client.svc.usb.poll_once()
    assert client.get("/api/usb/devices").get_json()["data"][0]["device_id"] == "DEV"


def test_config_directories_add_remove_and_validation(client, dirs):
    new = dirs["root"] / "extra"
    new.mkdir()
    r = client.post("/api/config/directories", json={"action": "add", "path": str(new)})
    assert r.status_code == 200 and str(new) in r.get_json()["data"]["monitored_directories"]
    r = client.post("/api/config/directories", json={"action": "remove", "path": str(new)})
    assert str(new) not in r.get_json()["data"]["monitored_directories"]
    assert client.post("/api/config/directories", json={"action": "add", "path": str(dirs["root"] / "ghost")}).status_code == 400
    assert client.post("/api/config/directories", json={"action": "zap"}).status_code == 400
    assert client.post("/api/config/directories", data="not json").status_code == 400
    assert client.get("/api/config").get_json()["data"]["sensitive_rules"]["keywords" if False else "filename_keywords"]


def test_monitoring_start_stop(client):
    assert client.post("/api/monitoring/start").get_json()["data"]["running"] is True
    assert client.get("/api/status").get_json()["data"]["file_monitor"]["running"] is True
    assert client.post("/api/monitoring/stop").get_json()["data"]["running"] is False
    assert client.post("/api/monitoring/pause").status_code == 400


def test_partial_config_still_has_default_sensitive_rules_and_exclusions():
    from app.config import Config
    from app.file_monitor import FileClassifier
    c = FileClassifier(Config({"monitored_directories": []}))
    assert c.classify("/x/confidential.txt")[0] is True
    assert c.is_excluded("/x/scratch.tmp") is True
