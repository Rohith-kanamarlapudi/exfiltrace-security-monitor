import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Config  # noqa: E402
from app.db import Database  # noqa: E402
from app.usb.base import UsbBackend, normalize_device  # noqa: E402


class FakeUsbBackend(UsbBackend):
    """Mocked USB backend: tests mutate `devices` to simulate insertion / removal."""
    name = "fake"

    def __init__(self):
        self.devices = []
        self.fail_with = None

    def snapshot(self):
        if self.fail_with:
            raise self.fail_with
        return [normalize_device(d) for d in self.devices]


def make_device(mount, device_id="USBSTOR\\DISK&VEN_GENERIC\\0001&0", **kw):
    d = {"device_id": device_id, "name": "Generic Flash Disk", "vendor_id": "0781", "product_id": "5567",
         "serial_number": "0001", "mounts": [str(mount)], "volume_label": "USB", "filesystem": "FAT32",
         "size_bytes": 8 * 1024**3}
    d.update(kw)
    return d


def wait_for(predicate, timeout=6.0, interval=0.05):
    end = time.time() + timeout
    while time.time() < end:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


@pytest.fixture
def dirs(tmp_path):
    monitored = tmp_path / "docs"
    usb_mount = tmp_path / "usbdrive"
    monitored.mkdir()
    usb_mount.mkdir()
    return {"root": tmp_path, "monitored": monitored, "usb": usb_mount}


@pytest.fixture
def config(dirs):
    return Config({
        "monitored_directories": [str(dirs["monitored"])],
        "database_path": str(dirs["root"] / "test.db"),
        "dedupe_window_seconds": 0.3,
        "detection": {"stable_check_interval_seconds": 0.01, "bulk_file_threshold": 4,
                      "bulk_window_seconds": 60, "correlation_window_seconds": 600},
        "sensitive_rules": {"extensions": [".kdbx", ".pem"], "filename_keywords": ["confidential", "password"],
                            "directories": ["hr"]},
        "exclusions": {"patterns": ["*.tmp", "~$*"], "directories": [".git"]},
    })


@pytest.fixture
def db(config):
    return Database(config.database_path)


@pytest.fixture
def backend():
    return FakeUsbBackend()
