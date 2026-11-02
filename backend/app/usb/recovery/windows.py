"""Read-only Windows volume access and fail-closed destination checks."""
import ctypes
import json
import os
import re
import subprocess
from contextlib import contextmanager
from pathlib import Path


def inventory():
    script = r"""$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
$rows=@(foreach($disk in Get-CimInstance Win32_DiskDrive){
 foreach($part in Get-CimAssociatedInstance -InputObject $disk -Association Win32_DiskDriveToDiskPartition){
  foreach($v in Get-CimAssociatedInstance -InputObject $part -Association Win32_LogicalDiskToPartition){
   [pscustomobject]@{mount=($v.DeviceID+'\');filesystem=$v.FileSystem;diskId=$disk.PNPDeviceID;
    diskPath=$disk.DeviceID;diskNumber=[int]$disk.Index;partitionSize=[long]$part.Size;usb=($disk.InterfaceType -eq 'USB' -or $disk.PNPDeviceID -like 'USBSTOR*')}
  }
 }
})
ConvertTo-Json -InputObject $rows -Compress
"""
    if os.name != 'nt':
        raise ValueError('Physical acquisition is supported only on Windows.')
    result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, text=True, encoding='utf-8', timeout=30)
    if result.returncode:
        raise ValueError('Windows storage query failed: ' + result.stderr.strip()[:1000])
    return json.loads(result.stdout)


def local_path(value, directory=True):
    if not isinstance(value, str) or not value or '\x00' in value:
        raise ValueError('Enter a full existing local path.')
    path = Path(value)
    if not path.is_absolute():
        raise ValueError('An absolute path is required.')
    path = path.resolve(strict=True)
    if (directory and not path.is_dir()) or (not directory and not path.is_file()):
        raise ValueError('Expected an existing ' + ('folder.' if directory else 'image file.'))
    if os.name == 'nt':
        if not re.match(r'^[A-Za-z]:\\', str(path)):
            raise ValueError('Use an internal local disk, not a network or device path.')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        root = ctypes.create_unicode_buffer(32768)
        if not kernel.GetVolumePathNameW(str(path), root, len(root)):
            raise ctypes.WinError(ctypes.get_last_error())
        # Reject folder-mounted volumes as well as removable drives. Prove the
        # resolved destination belongs to an internal disk, including fixed USBs.
        if root.value.upper() != path.anchor.upper() or kernel.GetDriveTypeW(root.value) != 3:
            raise ValueError('Use a drive-letter folder on an internal fixed disk.')
        matches = [v for v in inventory() if v['mount'].upper() == root.value.upper()]
        if len(matches) != 1 or matches[0]['usb']:
            raise ValueError('Destination/import must be on a verified internal disk, never a USB disk.')
    return path


@contextmanager
def open_volume(mount, disk_number):
    import msvcrt
    from ctypes import wintypes
    if not re.fullmatch(r'[A-Za-z]:\\', mount):
        raise ValueError('Only mounted drive-letter volumes are supported.')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    # GENERIC_READ, SHARE_READ | SHARE_WRITE, OPEN_EXISTING. No write access,
    # locking, dismounting, driver changes or volume-control IOCTLs.
    handle = create('\\\\.\\' + mount[:2], 0x80000000, 3, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        # Read-only STORAGE_GET_DEVICE_NUMBER verifies the opened handle, closing
        # the drive-letter reassignment race between enumeration and CreateFile.
        values = (wintypes.DWORD * 3)()
        returned = wintypes.DWORD()
        ioctl = kernel.DeviceIoControl
        ioctl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                          ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        ioctl.restype = wintypes.BOOL
        if not ioctl(handle, 0x2D1080, None, 0, values, ctypes.sizeof(values), ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if values[1] != disk_number:
            raise ValueError('Drive-letter mapping changed before opening the source; acquisition refused.')
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle(wintypes.HANDLE(handle))
        raise
    with os.fdopen(fd, 'rb', buffering=0) as stream:
        yield stream
