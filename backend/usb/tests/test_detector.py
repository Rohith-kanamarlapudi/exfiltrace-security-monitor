"""Unit tests for BadUSB and impersonation detection engine."""
from __future__ import annotations

import pytest
from backend.usb.detector import BadUsbDetector
from backend.usb.models import DeviceFingerprint, DeviceStatus, TrustStatus, UsbDevice


def test_keyboard_on_storage_flagged_critical(detector):
    fp = DeviceFingerprint(
        manufacturer="Generic",
        product="Flash Disk",
        interfaces=["Mass Storage (SCSI)", "HID Keyboard"],
    )
    dev = UsbDevice(
        id="test-badusb",
        name="Flash Disk",
        vendor_id="0781",
        product_id="5567",
        serial_number="0000000000000001",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp,
    )
    risk, status, checks, alerts, notes = detector.evaluate_device(dev)

    assert status == DeviceStatus.CRITICAL
    assert risk >= 70
    assert any("HID Keyboard" in n for n in notes.split(". "))
    assert any(a.rule == "UNEXPECTED_HID_KEYBOARD_ON_STORAGE" for a in alerts)
    # Check 4 should fail
    check4 = [c for c in checks if "Interface set" in c.label][0]
    assert check4.pass_check is False


def test_legit_peripherals_are_safe(detector):
    # Logitech keyboard + mouse receiver
    fp_logi = DeviceFingerprint(
        manufacturer="Logitech",
        product="USB Receiver",
        interfaces=["HID Keyboard", "HID Mouse"],
    )
    dev_logi = UsbDevice(
        id="test-logi",
        name="Logitech USB Receiver",
        vendor_id="046D",
        product_id="C52B",
        serial_number="LGT-8F21A09C",
        device_class="HID (03h)",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp_logi,
        seen_count=5,
    )
    risk, status, checks, alerts, notes = detector.evaluate_device(dev_logi, historical_seen=True)

    assert status == DeviceStatus.SAFE
    assert risk < 30
    assert len(alerts) == 0
    assert all(c.pass_check is True for c in checks)


def test_known_exploit_hardware_signature(detector):
    fp = DeviceFingerprint(
        manufacturer="Atmel",
        product="LUFA Keyboard",
        interfaces=["HID Keyboard"],
    )
    # 03EB:2401 is Hak5 Rubber Ducky
    dev_ducky = UsbDevice(
        id="test-ducky",
        name="Rubber Ducky",
        vendor_id="03EB",
        product_id="2401",
        serial_number="DUCKY01",
        device_class="HID (03h)",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp,
    )
    risk, status, checks, alerts, notes = detector.evaluate_device(dev_ducky)

    assert status in (DeviceStatus.CRITICAL, DeviceStatus.SUSPICIOUS)
    assert any("Rubber Ducky" in a.reason for a in alerts)


def test_vendor_impersonation_mismatch(detector):
    # Claims SanDisk VID 0781 but manufacturer says "Teensyduino"
    fp = DeviceFingerprint(
        manufacturer="Teensyduino",
        product="Storage Device",
        interfaces=["Mass Storage (SCSI)"],
    )
    dev = UsbDevice(
        id="test-impersonator",
        name="Storage Device",
        vendor_id="0781",
        product_id="5583",
        serial_number="1234567890AB",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp,
    )
    risk, status, checks, alerts, notes = detector.evaluate_device(dev)

    assert status == DeviceStatus.SUSPICIOUS
    check2 = [c for c in checks if "Manufacturer string" in c.label][0]
    assert check2.pass_check is False


def test_bogus_serial_flagged_for_storage(detector):
    fp = DeviceFingerprint(
        manufacturer="SanDisk",
        product="Ultra",
        interfaces=["Mass Storage (SCSI)"],
    )
    dev = UsbDevice(
        id="test-bogus-serial",
        name="SanDisk Ultra",
        vendor_id="0781",
        product_id="5583",
        serial_number="0000000000000001",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp,
    )
    risk, status, checks, alerts, notes = detector.evaluate_device(dev)

    check3 = [c for c in checks if "Serial number format" in c.label][0]
    assert check3.pass_check is False


def test_short_lived_hid_injection_flagged(detector):
    fp = DeviceFingerprint(
        manufacturer="Generic",
        product="Keyboard",
        interfaces=["HID Keyboard"],
    )
    dev = UsbDevice(
        id="test-short-hid",
        name="HID Keyboard",
        vendor_id="16C0",
        product_id="27DB",
        serial_number="N/A",
        device_class="HID (03h)",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp,
        trust_status=TrustStatus.UNKNOWN.value,
    )
    risk, status, checks, alerts, notes = detector.evaluate_device(
        dev, duration_seconds=5.0, historical_seen=False
    )

    assert any(a.rule == "SHORT_LIVED_HID_INJECTION" for a in alerts)
    assert any("5.0s" in n for n in notes.split(". "))


def test_trust_override_lowers_risk(detector):
    fp = DeviceFingerprint(
        manufacturer="Custom",
        product="Internal Dongle",
        interfaces=["Vendor Specific"],
    )
    dev = UsbDevice(
        id="test-trusted-custom",
        name="Custom Dongle",
        vendor_id="FFFF",
        product_id="0001",
        serial_number="CUSTOM-99",
        device_class="Vendor Specific",
        connected_at="2026-10-12T10:00:00Z",
        fingerprint=fp,
        trust_status=TrustStatus.TRUSTED.value,
    )
    risk, status, checks, alerts, notes = detector.evaluate_device(dev)

    assert status == DeviceStatus.SAFE
