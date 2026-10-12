"""Simulation engine and attack scenario generator for USB Forensics & BadUSB."""
from __future__ import annotations

import time
from typing import Dict, List

from .models import (
    DeviceFingerprint,
    DeviceStatus,
    FingerprintCheck,
    TrustStatus,
    UsbDevice,
)


def get_scenario_devices() -> list[UsbDevice]:
    """Generates the 6 canonical scenarios matching the ExfilTrace forensic specification."""

    # 1. Legit peripheral: Logitech USB Receiver (SAFE, TRUSTED)
    fp_logi = DeviceFingerprint(
        manufacturer="Logitech",
        product="USB Receiver",
        usb_version="2.00",
        bcd_device="12.11",
        max_power="98 mA",
        interfaces=["HID Keyboard", "HID Mouse"],
        notes="Known peripheral. Allow-listed corporate peripheral.",
    )
    dev_logi = UsbDevice(
        id="usb-001",
        name="Logitech USB Receiver",
        vendor_id="046D",
        product_id="C52B",
        serial_number="LGT-8F21A09C",
        device_class="HID (03h)",
        connected_at="2026-10-01T09:12:44Z",
        disconnected_at=None,
        status="SAFE",
        trust_status="TRUSTED",
        session="USB-S-0409",
        fingerprint=fp_logi,
        seen_count=14,
    )
    fp_logi.compute_hash(dev_logi.vendor_id, dev_logi.product_id, dev_logi.serial_number)
    fp_logi.checks = [
        FingerprintCheck("VID/PID registered to claimed vendor", True, "Logitech (046D)"),
        FingerprintCheck("Manufacturer string matches vendor", True, "Logitech matches"),
        FingerprintCheck("Serial number format valid", True, "LGT-8F21A09C"),
        FingerprintCheck("Interface set matches device class", True, "HID Keyboard, Mouse"),
        FingerprintCheck("Seen on this host before", True, "Seen 14 times"),
    ]

    # 2. Legit storage: SanDisk Ultra Fit (SAFE, TRUSTED)
    fp_sandisk = DeviceFingerprint(
        manufacturer="SanDisk",
        product="Ultra Fit",
        usb_version="3.00",
        bcd_device="1.00",
        max_power="224 mA",
        interfaces=["Mass Storage (SCSI)"],
        notes="Company-issued encrypted drive. Normal copy operations only.",
    )
    dev_sandisk = UsbDevice(
        id="usb-002",
        name="SanDisk Ultra Fit",
        vendor_id="0781",
        product_id="5583",
        serial_number="4C530001230821115",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-04T16:40:05Z",
        disconnected_at="2026-10-04T17:02:31Z",
        status="SAFE",
        trust_status="TRUSTED",
        session="USB-S-0415",
        mounts=["E:\\"],
        fingerprint=fp_sandisk,
        seen_count=5,
    )
    fp_sandisk.compute_hash(dev_sandisk.vendor_id, dev_sandisk.product_id, dev_sandisk.serial_number)
    fp_sandisk.checks = [
        FingerprintCheck("VID/PID registered to claimed vendor", True, "SanDisk (0781)"),
        FingerprintCheck("Manufacturer string matches vendor", True, "SanDisk matches"),
        FingerprintCheck("Serial number format valid", True, "Valid standard serial"),
        FingerprintCheck("Interface set matches device class", True, "Mass Storage (SCSI)"),
        FingerprintCheck("Seen on this host before", True, "Seen 5 times"),
    ]

    # 3. BadUSB Impersonator: Generic Flash Disk impersonating SanDisk with hidden Keyboard (CRITICAL, SUSPICIOUS)
    fp_badusb = DeviceFingerprint(
        manufacturer="Generic",
        product="Flash Disk",
        usb_version="2.00",
        bcd_device="0.01",
        max_power="500 mA",
        interfaces=["Mass Storage (SCSI)", "HID Keyboard"],
        notes='VID 0781 belongs to SanDisk, but manufacturer string reads "Generic", serial is placeholder "0000000000000001", and an unexpected HID keyboard interface is exposed. Impersonating a SanDisk drive with keystroke injection capabilities.',
    )
    dev_badusb = UsbDevice(
        id="usb-003",
        name="Generic Flash Disk",
        vendor_id="0781",
        product_id="5567",
        serial_number="0000000000000001",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-05T14:02:11Z",
        disconnected_at=None,
        status="CRITICAL",
        trust_status="SUSPICIOUS",
        session="USB-S-0417",
        risk_score=95,
        mounts=["E:\\"],
        fingerprint=fp_badusb,
        seen_count=1,
    )
    fp_badusb.compute_hash(dev_badusb.vendor_id, dev_badusb.product_id, dev_badusb.serial_number)
    fp_badusb.checks = [
        FingerprintCheck("VID/PID registered to claimed vendor", True, "SanDisk (0781)"),
        FingerprintCheck("Manufacturer string matches vendor", False, "Claimed 'Generic' vs expected 'SanDisk'"),
        FingerprintCheck("Serial number format valid", False, "Placeholder 0000000000000001"),
        FingerprintCheck("Interface set matches device class", False, "Unexpected HID Keyboard exposed!"),
        FingerprintCheck("Seen on this host before", False, "First connection"),
    ]

    # 4. Personal Unregistered USB Drive: Kingston DataTraveler 3.0 (SUSPICIOUS)
    fp_kingston = DeviceFingerprint(
        manufacturer="Kingston",
        product="DataTraveler 3.0",
        usb_version="3.00",
        bcd_device="1.10",
        max_power="200 mA",
        interfaces=["Mass Storage (SCSI)"],
        notes="Descriptor is genuine, but this is a personal, unregistered device not present in the allow-list.",
    )
    dev_kingston = UsbDevice(
        id="usb-004",
        name="Kingston DataTraveler 3.0",
        vendor_id="0951",
        product_id="1666",
        serial_number="60A44C413C8CF1B0",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-05T11:26:50Z",
        disconnected_at="2026-10-05T11:48:09Z",
        status="SUSPICIOUS",
        trust_status="UNKNOWN",
        session="USB-S-0416",
        risk_score=40,
        mounts=["E:\\"],
        fingerprint=fp_kingston,
        seen_count=1,
    )
    fp_kingston.compute_hash(dev_kingston.vendor_id, dev_kingston.product_id, dev_kingston.serial_number)
    fp_kingston.checks = [
        FingerprintCheck("VID/PID registered to claimed vendor", True, "Kingston (0951)"),
        FingerprintCheck("Manufacturer string matches vendor", True, "Kingston matches"),
        FingerprintCheck("Serial number format valid", True, "Valid standard serial"),
        FingerprintCheck("Interface set matches device class", True, "Mass Storage (SCSI)"),
        FingerprintCheck("Seen on this host before", False, "First time on this host"),
    ]

    # 5. Legit External SSD: Samsung Portable SSD T7 (SAFE, TRUSTED)
    fp_samsung = DeviceFingerprint(
        manufacturer="Samsung",
        product="PSSD T7",
        usb_version="3.20",
        bcd_device="1.00",
        max_power="896 mA",
        interfaces=["Mass Storage (UASP)"],
        notes="IT-managed backup drive with genuine hardware descriptor.",
    )
    dev_samsung = UsbDevice(
        id="usb-005",
        name="Samsung Portable SSD T7",
        vendor_id="04E8",
        product_id="61F5",
        serial_number="S5SXNS0R412987K",
        device_class="Mass Storage (08h)",
        connected_at="2026-10-03T10:05:19Z",
        disconnected_at="2026-10-03T10:31:44Z",
        status="SAFE",
        trust_status="TRUSTED",
        session="USB-S-0412",
        fingerprint=fp_samsung,
        seen_count=8,
    )
    fp_samsung.compute_hash(dev_samsung.vendor_id, dev_samsung.product_id, dev_samsung.serial_number)
    fp_samsung.checks = [
        FingerprintCheck("VID/PID registered to claimed vendor", True, "Samsung (04E8)"),
        FingerprintCheck("Manufacturer string matches vendor", True, "Samsung matches"),
        FingerprintCheck("Serial number format valid", True, "Valid standard serial"),
        FingerprintCheck("Interface set matches device class", True, "Mass Storage (UASP)"),
        FingerprintCheck("Seen on this host before", True, "Seen 8 times"),
    ]

    # 6. Short-lived Teensyduino Keystroke Injector (SUSPICIOUS)
    fp_teensy = DeviceFingerprint(
        manufacturer="Teensyduino",
        product="Keyboard/Mouse/Joystick",
        usb_version="2.00",
        bcd_device="2.80",
        max_power="100 mA",
        interfaces=["HID Keyboard", "HID Mouse"],
        notes="Development-board HID connected for 7 seconds. Short-lived keyboard emulator indicative of scripted keystroke payload injection.",
    )
    dev_teensy = UsbDevice(
        id="usb-006",
        name="Unknown HID Device",
        vendor_id="16C0",
        product_id="27DB",
        serial_number="N/A",
        device_class="HID (03h)",
        connected_at="2026-10-02T13:44:02Z",
        disconnected_at="2026-10-02T13:44:09Z",
        status="SUSPICIOUS",
        trust_status="SUSPICIOUS",
        session="USB-S-0411",
        risk_score=65,
        fingerprint=fp_teensy,
        seen_count=1,
    )
    fp_teensy.compute_hash(dev_teensy.vendor_id, dev_teensy.product_id, dev_teensy.serial_number)
    fp_teensy.checks = [
        FingerprintCheck("VID/PID registered to claimed vendor", True, "Teensyduino (16C0)"),
        FingerprintCheck("Manufacturer string matches vendor", True, "Matches"),
        FingerprintCheck("Serial number format valid", False, "Missing serial (N/A)"),
        FingerprintCheck("Interface set matches device class", True, "HID Keyboard, Mouse"),
        FingerprintCheck("Seen on this host before", False, "First connection; disconnected in 7s"),
    ]

    return [dev_logi, dev_sandisk, dev_badusb, dev_kingston, dev_samsung, dev_teensy]
