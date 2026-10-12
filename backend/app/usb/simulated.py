"""Simulated USB backend: devices are read from a JSON file you edit by hand.

Use it to demo or test the whole pipeline without hardware (and on non-Windows machines).
File format: {"devices": [ {device dict}, ... ]}   (see README, "Test USB detection")
Add a device to the list = "insert", remove it = "remove". `mounts` can be any folder.
"""
import json
import os

from .base import UsbBackend, UsbBackendError, normalize_device


class SimulatedUsbBackend(UsbBackend):
    name = "simulated"

    def __init__(self, path):
        self.path = path

    def snapshot(self):
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return [normalize_device(d) for d in data.get("devices", [])]
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            raise UsbBackendError(f"Cannot read simulated USB file {self.path}: {exc}") from exc
