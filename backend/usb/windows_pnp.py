"""Native Windows USB device enumeration and PnP descriptor extraction."""
from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, Optional

from .config import KNOWN_VENDORS
from .models import DeviceFingerprint, UsbDevice

log = logging.getLogger("exfiltrace.usb.pnp")

# PowerShell script to enumerate all USB PnP devices with hardware IDs and driver classes
PS_ENUMERATE_USB = r"""
$ErrorActionPreference = 'SilentlyContinue'
$items = @()

$pnpDevices = Get-CimInstance Win32_PnPEntity | Where-Object {
    $_.DeviceID -like 'USB\*' -or
    $_.PNPDeviceID -like 'USB\*' -or
    $_.PNPDeviceID -like 'USBSTOR\*' -or
    $_.PNPClass -eq 'USB' -or
    $_.PNPClass -eq 'HIDClass' -or
    $_.Service -eq 'USBSTOR'
}

foreach ($dev in $pnpDevices) {
    $hardwareId = ($dev.HardwareID | Select-Object -First 1)
    $compatIds = @($dev.CompatibleID)
    
    $items += [pscustomobject]@{
        DeviceId = $dev.DeviceID
        Name = $dev.Name
        Manufacturer = $dev.Manufacturer
        Description = $dev.Description
        PNPClass = $dev.PNPClass
        Service = $dev.Service
        Status = $dev.Status
        HardwareID = $hardwareId
        CompatibleIDs = $compatIds
    }
}

$items | ConvertTo-Json -Depth 4 -Compress
"""

VID_PID_REGEX = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", re.IGNORECASE)


def extract_vid_pid(hardware_id: str, device_id: str) -> tuple[Optional[str], Optional[str]]:
    for target in (hardware_id or "", device_id or ""):
        m = VID_PID_REGEX.search(target)
        if m:
            return m.group(1).upper(), m.group(2).upper()
    return None, None


def extract_serial(device_id: str) -> str:
    r"""Extracts serial from PnP instance ID e.g. USB\VID_0781&PID_5583\4C530001230821115"""
    if not device_id or "\\" not in device_id:
        return "N/A"
    tail = device_id.rsplit("\\", 1)[-1]
    # In Windows, trailing &0 or &1 indicates composite interface index
    if "&" in tail and len(tail.split("&")) > 2:
        return tail.split("&")[0]
    return tail


def map_class_and_interfaces(pnp_class: str, service: str, name: str, compat_ids: list[str]) -> tuple[str, list[str]]:
    """Determine human-readable device class and interface list."""
    interfaces: list[str] = []
    pnp_lower = (pnp_class or "").lower()
    serv_lower = (service or "").lower()
    name_lower = (name or "").lower()
    compat_str = " ".join(compat_ids or []).lower()

    is_keyboard = "keyboard" in name_lower or "kbd" in serv_lower or "class_03&subclass_01&prot_01" in compat_str
    is_mouse = "mouse" in name_lower or "mou" in serv_lower or "class_03&subclass_01&prot_02" in compat_str
    is_storage = "disk" in pnp_lower or "usbstor" in serv_lower or "class_08" in compat_str

    if is_keyboard:
        interfaces.append("HID Keyboard")
    if is_mouse:
        interfaces.append("HID Mouse")
    if is_storage:
        interfaces.append("Mass Storage (SCSI)")

    # Composite detection
    if "composite" in name_lower or "usbccgp" in serv_lower:
        device_class = "Composite (00h)"
        if not interfaces:
            interfaces.append("Composite Child Endpoints")
    elif is_storage:
        device_class = "Mass Storage (08h)"
    elif is_keyboard or is_mouse or "hid" in pnp_lower:
        device_class = "HID (03h)"
    elif "hub" in pnp_lower or "usbhub" in serv_lower:
        device_class = "Hub (09h)"
        interfaces.append("Hub Port Repeater")
    elif "bluetooth" in pnp_lower or "wireless" in pnp_lower:
        device_class = "Wireless Controller (E0h)"
        interfaces.append("RF Controller")
    elif "media" in pnp_lower or "audio" in pnp_lower:
        device_class = "Audio (01h)"
        interfaces.append("Audio Streaming")
    else:
        device_class = f"{pnp_class or 'Generic'} Device"
        if not interfaces:
            interfaces.append("Vendor Specific")

    return device_class, interfaces


def query_windows_usb_devices() -> list[UsbDevice]:
    """Execute PowerShell PnP discovery and return normalized UsbDevice objects."""
    if sys.platform != "win32":
        return []

    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                PS_ENUMERATE_USB,
            ],
            capture_output=True,
            text=True,
            timeout=25,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            log.warning("PowerShell USB enumeration returned empty or failed: %s", proc.stderr[:200])
            return []

        raw_data = json.loads(proc.stdout.strip())
        items = raw_data if isinstance(raw_data, list) else [raw_data]
    except Exception as exc:
        log.warning("Windows USB discovery failed: %s", exc)
        return []

    devices: list[UsbDevice] = []
    seen_ids: set[str] = set()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for idx, item in enumerate(items):
        dev_id_raw = item.get("DeviceId") or item.get("HardwareID") or f"usb-win-{idx}"
        vid, pid = extract_vid_pid(item.get("HardwareID") or "", dev_id_raw)
        if not vid or not pid:
            continue

        unique_key = f"{vid}:{pid}:{extract_serial(dev_id_raw)}"
        if unique_key in seen_ids:
            continue
        seen_ids.add(unique_key)

        mfg = item.get("Manufacturer") or KNOWN_VENDORS.get(vid) or "Unknown Manufacturer"
        name = item.get("Name") or item.get("Description") or f"USB Device ({vid}:{pid})"
        serial = extract_serial(dev_id_raw)
        compat = [c for c in (item.get("CompatibleIDs") or []) if c is not None]
        dev_class, interfaces = map_class_and_interfaces(item.get("PNPClass"), item.get("Service"), name, compat)

        fp = DeviceFingerprint(
            manufacturer=mfg,
            product=name,
            usb_version="2.00",
            bcd_device="1.00",
            max_power="100 mA",
            interfaces=interfaces,
        )
        fp.compute_hash(vid, pid, serial)

        device = UsbDevice(
            id=f"usb-{vid.lower()}-{pid.lower()}-{idx:02d}",
            name=name,
            vendor_id=vid,
            product_id=pid,
            serial_number=serial,
            device_class=dev_class,
            connected_at=now_utc,
            disconnected_at=None,
            status="SAFE",
            trust_status="UNKNOWN",
            session=f"USB-S-WIN{idx:02d}",
            fingerprint=fp,
            seen_count=1,
        )
        devices.append(device)

    return devices
