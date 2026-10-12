"""USB monitoring. OS-specific code lives in windows.py / simulated.py behind the UsbBackend interface."""
import sys

from .base import UsbBackend, UsbBackendError  # noqa: F401
from .simulated import SimulatedUsbBackend
from .windows import WindowsUsbBackend


class NullUsbBackend(UsbBackend):
    """Used on systems with no real backend: reports no devices instead of crashing."""
    name = "none"

    def snapshot(self):
        return []


def create_backend(config):
    usb = config["usb"]
    choice = usb.get("backend", "auto")
    sim_path = config.resolve_path(usb.get("simulated_file", "data/simulated_usb.json"))
    if choice == "simulated":
        return SimulatedUsbBackend(sim_path)
    if choice == "windows" or (choice == "auto" and sys.platform == "win32"):
        return WindowsUsbBackend()
    if choice in ("none", "off"):
        return NullUsbBackend()
    # auto on Linux/macOS: no real backend implemented -> simulated file (empty unless the user creates it)
    return SimulatedUsbBackend(sim_path)
