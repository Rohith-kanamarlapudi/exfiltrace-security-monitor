"""Windows USB storage backend.

Uses PowerShell + CIM (no extra Python packages). It lists USB disks, their volumes
(drive letters) and tries to recover VID/PID from the matching USB PnP entity.
Windows only; on other systems it raises UsbBackendError.
"""
import json
import re
import subprocess
import sys

from .base import UsbBackend, UsbBackendError, normalize_device

POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$disks = @()
foreach ($disk in (Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' -or $_.PNPDeviceID -like 'USBSTOR*' })) {
  $vols = @()
  $escaped = $disk.DeviceID.Replace('\', '\\')
  foreach ($part in (Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$escaped'} WHERE AssocClass=Win32_DiskDriveToDiskPartition")) {
    foreach ($ld in (Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($part.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition")) {
      $vols += [pscustomobject]@{ drive = $ld.DeviceID; label = $ld.VolumeName; fs = $ld.FileSystem; size = $ld.Size }
    }
  }
  $disks += [pscustomobject]@{ pnp = $disk.PNPDeviceID; model = $disk.Model; serial = $disk.SerialNumber; size = $disk.Size; volumes = @($vols) }
}
$ids = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.DeviceID -like 'USB\VID_*' } | ForEach-Object { $_.DeviceID })
[pscustomobject]@{ disks = @($disks); usb_ids = @($ids) } | ConvertTo-Json -Depth 6 -Compress
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
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as exc:
        raise UsbBackendError(f"Unreadable PowerShell output: {exc}") from exc
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

    def snapshot(self):
        if sys.platform != "win32":
            raise UsbBackendError("Windows USB backend can only run on Windows")
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", POWERSHELL_SCRIPT],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UsbBackendError(f"PowerShell failed: {exc}") from exc
        if proc.returncode != 0:
            raise UsbBackendError(f"PowerShell exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return parse_powershell_output(proc.stdout)
