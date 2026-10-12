"""Windows physical USB inventory with cached native PnP metadata inspection.

Uses PowerShell + CIM (no extra Python packages). It lists USB disks, their volumes
(drive letters) and tries to recover VID/PID from the matching USB PnP entity.
Windows only; on other systems it raises UsbBackendError.
"""
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from .inspection import inspect_nodes
from .setupapi import enumerate_nodes

from .base import UsbBackend, UsbBackendError, normalize_device

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$disks = @()
foreach ($disk in (Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' -or $_.PNPDeviceID -like 'USBSTOR*' })) {
  $vols = @()
  # Use the provider's CIM object path rather than rebuilding/escaping DeviceID.
  foreach ($part in (Get-CimAssociatedInstance -InputObject $disk -Association Win32_DiskDriveToDiskPartition -ResultClassName Win32_DiskPartition)) {
    foreach ($ld in (Get-CimAssociatedInstance -InputObject $part -Association Win32_LogicalDiskToPartition -ResultClassName Win32_LogicalDisk)) {
      $vols += [pscustomobject]@{ drive = $ld.DeviceID; label = $ld.VolumeName; fs = $ld.FileSystem; size = $ld.Size }
    }
  }
  $disks += [pscustomobject]@{ pnp = $disk.PNPDeviceID; model = $disk.Model; serial = $disk.SerialNumber; size = $disk.Size; volumes = @($vols) }
}
$pnp = @(Get-CimInstance Win32_PnPEntity)
$ids = @($pnp | Where-Object { $_.DeviceID -like 'USB\VID_*' } | ForEach-Object { $_.DeviceID })
[pscustomobject]@{ disks = @($disks); usb_ids = @($ids); present_ids = @($pnp | ForEach-Object { $_.DeviceID }) } | ConvertTo-Json -Depth 6 -Compress
"""

_VIDPID = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})")


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _serial_from_pnp(pnp):
    """USBSTOR\\DISK&VEN_X&PROD_Y&REV_1\\<serial>&0 -> <serial>"""
    tail = (pnp or "").rsplit("\\", 1)[-1]
    return tail.rsplit("&", 1)[0] if "&" in tail else tail


def _vendor_product_from_pnp(pnp):
    ven = re.search(r"VEN_([^&\\]+)", pnp or "")
    prod = re.search(r"PROD_([^&\\]+)", pnp or "")
    return (ven.group(1).replace("_", " ") if ven else None, prod.group(1).replace("_", " ") if prod else None)


def parse_powershell_output(text):
    """Pure function (unit tested on any OS): PowerShell JSON -> list of normalized devices."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsbBackendError(f"Unreadable PowerShell output: {exc}") from exc
    if not isinstance(data, dict) or not all(key in data for key in ("disks", "usb_ids")):
        raise UsbBackendError("Invalid PowerShell snapshot: expected disks and usb_ids")
    usb_ids = _as_list(data.get("usb_ids"))
    devices = []
    for disk in _as_list(data.get("disks")):
        pnp = disk.get("pnp") or ""
        serial = _serial_from_pnp(pnp)
        vid = pid = None
        for uid in usb_ids:
            if serial and uid.upper().endswith("\\" + serial.upper()):
                m = _VIDPID.search(uid)
                if m:
                    vid, pid = m.group(1), m.group(2)
                    break
        vols = _as_list(disk.get("volumes"))
        first = vols[0] if vols else {}
        devices.append(normalize_device({
            "device_id": pnp or disk.get("serial") or disk.get("model"),
            "name": (disk.get("model") or "").strip() or None,
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": serial or (disk.get("serial") or "").strip() or None,
            "mounts": [v["drive"] + "\\" for v in vols if v.get("drive")],
            "volume_label": first.get("label"),
            "filesystem": first.get("fs"),
            "size_bytes": disk.get("size") or first.get("size"),
        }))
    return devices


class WindowsUsbBackend(UsbBackend):
    name = "windows"

    def __init__(self):
        self._inspection = None
        self._signature = None
        self._inspected_at = 0
        self.snapshot_complete = True
        self._collected_at = None

    def snapshot(self):
        if sys.platform != "win32":
            raise UsbBackendError("Windows USB backend can only run on Windows")
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", POWERSHELL_SCRIPT],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UsbBackendError(f"PowerShell failed: {exc}") from exc
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "no diagnostic output"
            raise UsbBackendError(f"PowerShell exited {proc.returncode}: {detail[:2000]}")
        disks = parse_powershell_output(proc.stdout)
        data = json.loads(proc.stdout)
        # Legacy/captured storage snapshots remain accepted by the pure parser.
        if 'present_ids' not in data:
            return disks
        signature = tuple(sorted(str(i).upper() for i in data['present_ids'] if i))
        if signature != self._signature or time.monotonic() - self._inspected_at >= 60:
            payload = enumerate_nodes()
            # A disconnect between the two queries invalidates this cycle.
            prefixes = ('USB\\', 'USBSTOR\\', 'HID\\', 'SCSI\\')
            expected = {i for i in signature if i.startswith(prefixes)}
            actual = {n['instanceId'].upper() for n in payload.get('nodes', []) if n.get('instanceId', '').upper().startswith(prefixes)}
            if expected != actual:
                raise UsbBackendError('USB inventory changed during inspection; retrying next poll')
            self._inspection = payload
            self._signature = signature
            self._inspected_at = time.monotonic()
            self._collected_at = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        devices = inspect_nodes(self._inspection, disks)
        self.snapshot_complete = (not any(n.get('errors') for n in self._inspection['nodes']) and
                                  all(d['inspection']['completeness'] == 'complete' for d in devices))
        for d in devices:
            d['observationSource'] = 'windows'
            d['inspection']['collectedAt'] = self._collected_at
        if not self.snapshot_complete:
            self._inspected_at = 0  # retry missing properties next cycle
        return devices
