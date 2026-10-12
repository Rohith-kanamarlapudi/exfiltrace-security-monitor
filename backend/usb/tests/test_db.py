"""Unit tests for USB Forensics database persistence and trust management."""
from __future__ import annotations

import pytest
from backend.usb.db import UsbForensicsDb
from backend.usb.models import BadUsbAlert, DeviceFingerprint, UsbDevice


def test_device_upsert_and_fetch(temp_db):
    fp = DeviceFingerprint(manufacturer="Logitech", product="Mouse", interfaces=["HID Mouse"])
    dev = UsbDevice(
        id="dev-01",
        name="Logitech Mouse",
        vendor_id="046D",
        product_id="C077",
        serial_number="M-1234",
        device_class="HID (03h)",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp,
    )
    temp_db.save_device(dev)

    fetched = temp_db.get_device("dev-01")
    assert fetched is not None
    assert fetched.name == "Logitech Mouse"
    assert fetched.vendor_id == "046D"
    assert fetched.seen_count == 1

    # Re-connect should preserve trust and increase seen_count
    dev.connected_at = "2026-10-12T11:00:00Z"
    dev.disconnected_at = None
    temp_db.save_device(dev)

    fetched2 = temp_db.get_device("dev-01")
    assert fetched2.seen_count == 2


def test_trust_status_management(temp_db):
    dev = UsbDevice(
        id="dev-02",
        name="Generic Flash",
        vendor_id="0781",
        product_id="5567",
        serial_number="0001",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-12T10:00:00Z",
    )
    temp_db.save_device(dev)

    assert temp_db.get_device("dev-02").trust_status == "UNKNOWN"

    success = temp_db.set_trust_status("dev-02", "TRUSTED", "Audited by Security Team")
    assert success is True
    assert temp_db.get_device("dev-02").trust_status == "TRUSTED"

    # Set to suspicious
    temp_db.set_trust_status("dev-02", "SUSPICIOUS", "Failed hash verification")
    assert temp_db.get_device("dev-02").trust_status == "SUSPICIOUS"


def test_alerts_persistence_and_acknowledgement(temp_db):
    alert = BadUsbAlert(
        id="alt-01",
        device_id="dev-01",
        vendor_id="0781",
        product_id="5567",
        timestamp="2026-10-12T10:00:00Z",
        severity="CRITICAL",
        risk_score=90,
        rule="KEYBOARD_ON_STORAGE",
        reason="HID keyboard endpoint exposed",
        recommended_action="Unplug device",
        acknowledged=False,
    )
    temp_db.add_alert(alert)

    alerts = temp_db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].id == "alt-01"
    assert alerts[0].acknowledged is False

    # Acknowledge alert
    res = temp_db.acknowledge_alert("alt-01")
    assert res is True

    unack = temp_db.get_alerts(unack_only=True)
    assert len(unack) == 0


def test_mark_disconnected(temp_db):
    dev = UsbDevice(
        id="dev-03",
        name="Kingston Drive",
        vendor_id="0951",
        product_id="1666",
        serial_number="SN999",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-12T10:00:00Z",
    )
    temp_db.save_device(dev)
    assert temp_db.get_device("dev-03").disconnected_at is None

    temp_db.mark_disconnected("dev-03", "2026-10-12T10:15:00Z")
    fetched = temp_db.get_device("dev-03")
    assert fetched.disconnected_at == "2026-10-12T10:15:00Z"
