"""API contract and functional tests for USB Forensics endpoints."""
from __future__ import annotations

import pytest

EXPECTED_DEVICE_KEYS = {
    "id",
    "name",
    "vendorId",
    "productId",
    "serialNumber",
    "deviceClass",
    "connectedAt",
    "disconnectedAt",
    "status",
    "trustStatus",
    "session",
    "riskScore",
    "mounts",
    "seenCount",
    "fingerprint",
}

EXPECTED_FINGERPRINT_KEYS = {
    "manufacturer",
    "product",
    "usbVersion",
    "bcdDevice",
    "maxPower",
    "interfaces",
    "descriptorHash",
    "checks",
    "notes",
}


def test_get_usb_devices_schema_and_keys(client):
    res = client.get("/api/usb/devices")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)
    assert len(data) >= 1

    first = data[0]
    assert EXPECTED_DEVICE_KEYS.issubset(set(first.keys()))
    assert EXPECTED_FINGERPRINT_KEYS.issubset(set(first["fingerprint"].keys()))
    assert isinstance(first["fingerprint"]["checks"], list)
    assert first["status"] in ("SAFE", "SUSPICIOUS", "CRITICAL")


def test_get_usb_device_detail(client):
    res = client.get("/api/usb/devices/usb-001")
    assert res.status_code == 200
    data = res.get_json()
    assert data["id"] == "usb-001"
    assert data["vendorId"] == "046D"

    # Non-existent device returns 404
    res404 = client.get("/api/usb/devices/usb-nonexistent")
    assert res404.status_code == 404


def test_update_device_trust(client):
    res = client.post(
        "/api/usb/devices/usb-003/trust",
        json={"status": "TRUSTED", "reason": "Approved by security lead"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["device"]["trustStatus"] == "TRUSTED"

    # Invalid status returns 400
    res_bad = client.post("/api/usb/devices/usb-003/trust", json={"status": "INVALID"})
    assert res_bad.status_code == 400


def test_get_and_ack_alerts(client):
    res = client.get("/api/usb/alerts")
    assert res.status_code == 200
    alerts = res.get_json()
    assert isinstance(alerts, list)

    if alerts:
        first_id = alerts[0]["id"]
        ack_res = client.post(f"/api/usb/alerts/{first_id}/ack")
        assert ack_res.status_code == 200
        assert ack_res.get_json()["success"] is True


def test_simulate_scenario_injection(client):
    res = client.post("/api/usb/simulate", json={"scenario": "badusb_sandisk"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["device"]["status"] == "CRITICAL"
    assert data["device"]["id"] == "usb-003"


def test_usb_status_endpoint(client):
    res = client.get("/api/usb/status")
    assert res.status_code == 200
    status = res.get_json()
    assert "totalDevicesSeen" in status
    assert "connectedDevices" in status
    assert "criticalDevices" in status
