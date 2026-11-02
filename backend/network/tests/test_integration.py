"""Combined-backend integration without changing the shared API module."""

from __future__ import annotations

from backend.app.api import create_app
from backend.app.config import Config
from backend.app.service import MonitoringService
from backend.app.usb import NullUsbBackend
from backend.network import integration


def _shared_app(tmp_path):
    config = Config({
        "monitored_directories": [],
        "database_path": str(tmp_path / "shared.db"),
        "usb": {"backend": "none", "poll_interval_seconds": 60},
    })
    service = MonitoringService(config, usb_backend=NullUsbBackend(), async_detection=False)
    return create_app(service=service, autostart=False)


def test_network_routes_and_shared_health_coexist(temp_db, tmp_path):
    app = _shared_app(tmp_path)
    assert integration.register_network(app) is True
    client = app.test_client()

    assert client.get("/api/health").get_json() == {"status": "ok", "source": "live"}
    assert client.get("/api/network/events").status_code == 200
    assert client.get("/api/network/stats").status_code == 200
    assert client.get("/api/network/traffic").status_code == 200


def test_network_failure_leaves_shared_endpoints_available(temp_db, tmp_path, monkeypatch):
    def fail(_db_path=None):
        raise OSError("network database unavailable")

    monkeypatch.setattr(integration, "initialize_database", fail)
    app = _shared_app(tmp_path)
    assert integration.register_network(app) is False
    client = app.test_client()

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/usb/devices").status_code == 200
    assert client.get("/api/files/events").status_code == 200
    assert client.get("/api/files/stats").status_code == 200
    assert client.get("/api/network/events").status_code == 404


def test_blueprint_failure_leaves_shared_endpoints_available(temp_db, tmp_path, monkeypatch):
    app = _shared_app(tmp_path)

    def fail(*_args, **_kwargs):
        raise RuntimeError("network blueprint unavailable")

    monkeypatch.setattr(app, "register_blueprint", fail)
    assert integration.register_network(app) is False
    client = app.test_client()

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/status").status_code == 200
    assert client.get("/api/usb/devices").status_code == 200
    assert client.get("/api/files/events").status_code == 200
    assert client.get("/api/files/stats").status_code == 200
    assert client.get("/api/network/events").status_code == 404
