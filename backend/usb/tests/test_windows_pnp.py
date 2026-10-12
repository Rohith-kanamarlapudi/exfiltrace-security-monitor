"""Unit tests for Windows USB PnP parser functions."""
from __future__ import annotations

from backend.usb.windows_pnp import extract_serial, extract_vid_pid, map_class_and_interfaces


def test_extract_vid_pid():
    hw_id = "USB\\VID_0781&PID_5583&REV_0100"
    dev_id = "USB\\VID_0781&PID_5583\\4C530001230821115"

    vid, pid = extract_vid_pid(hw_id, dev_id)
    assert vid == "0781"
    assert pid == "5583"


def test_extract_serial():
    dev_id = "USB\\VID_0781&PID_5583\\4C530001230821115"
    assert extract_serial(dev_id) == "4C530001230821115"

    composite_child = "USB\\VID_046D&PID_C52B&MI_00\\7&12345&0&0000"
    assert extract_serial(composite_child) == "7"

    assert extract_serial("") == "N/A"


def test_map_class_and_interfaces():
    # Keyboard
    cls, ifaces = map_class_and_interfaces("HIDClass", "kbdhid", "HID Keyboard Device", ["USB\\Class_03&SubClass_01&Prot_01"])
    assert cls == "HID (03h)"
    assert "HID Keyboard" in ifaces

    # Storage
    cls2, ifaces2 = map_class_and_interfaces("DiskDrive", "USBSTOR", "SanDisk Ultra", ["USB\\Class_08"])
    assert cls2 == "Mass Storage (08h)"
    assert "Mass Storage (SCSI)" in ifaces2
