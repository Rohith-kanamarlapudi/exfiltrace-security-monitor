"""Configuration and rule thresholds for USB Forensics and BadUSB detection."""
from __future__ import annotations

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "data", "usb_forensics.db")

# Known USB Vendor IDs
KNOWN_VENDORS = {
    "046D": "Logitech",
    "0781": "SanDisk",
    "0951": "Kingston",
    "04E8": "Samsung",
    "054C": "Sony",
    "045E": "Microsoft",
    "03F0": "HP",
    "413C": "Dell",
    "05AC": "Apple",
    "1058": "Western Digital",
    "0BC2": "Seagate",
    "125F": "A-DATA",
    "8564": "Transcend",
    "13FE": "Phison Electronics",
    "090C": "Silicon Motion",
    "18A5": "Verbatim",
    "16C0": "Van Ooijen Technische Informatica (Teensy/V-USB)",
    "03EB": "Atmel Corp. (Hak5 / LUFA)",
    "2E8A": "Raspberry Pi",
    "1B4F": "SparkFun Electronics",
    "2341": "Arduino SA",
}

# Known Hardware Exploitation Tools / Attack Hardware IDs
KNOWN_EXPLOIT_VID_PID = {
    ("03EB", "2401"): "Hak5 USB Rubber Ducky (Atmel LUFA HID)",
    ("03EB", "0001"): "Hak5 USB Rubber Ducky DFU",
    ("16C0", "0478"): "Teensyduino Keystroke Injector",
    ("16C0", "0486"): "Teensyduino Composite HID",
    ("16C0", "27DB"): "Teensyduino Development Board",
    ("16C0", "05DF"): "Digispark ATTiny85 Keystroke Injector",
    ("1B4F", "9207"): "MalDuino BadUSB Script Injector",
    ("1B4F", "9208"): "MalDuino Elite BadUSB",
    ("2E8A", "0005"): "Raspberry Pi Pico Keystroke Injector",
    ("2E8A", "000A"): "Raspberry Pi Pico HID Payload Device",
}

# Placeholder / suspicious serial numbers
SUSPICIOUS_SERIAL_PATTERNS = {
    "0000000000000001",
    "000000000000",
    "00000000",
    "12345678",
    "123456789012",
    "ABCDEF123456",
    "DEMO",
    "N/A",
    "NONE",
    "NULL",
}

# Detection rule scores (0 - 100)
RULE_WEIGHTS = {
    "KEYBOARD_ON_STORAGE": 60,
    "KNOWN_EXPLOIT_HARDWARE": 55,
    "VENDOR_MISMATCH": 35,
    "BOGUS_SERIAL": 30,
    "SHORT_LIVED_HID": 40,
    "UNEXPECTED_COMPOSITE": 25,
    "UNREGISTERED_DEVICE": 15,
}

# Thresholds
RISK_THRESHOLD_SUSPICIOUS = 35
RISK_THRESHOLD_CRITICAL = 70

POLL_INTERVAL_SECONDS = float(os.environ.get("EXFILTRACE_USB_POLL_INTERVAL", "3.0"))
SHORT_LIVED_HID_THRESHOLD_SECONDS = 15.0
