"""USB backend interface. Anything OS-specific lives in a backend; the rest of the app only sees device dicts.

A device dict has these keys (None when the OS does not provide them):
    device_id, name, vendor_id, product_id, serial_number,
    mounts (list of drive letters / mount points), volume_label, filesystem, size_bytes
"""


class UsbBackendError(Exception):
    """Raised when the OS could not be queried (monitor keeps running and retries)."""


class UsbBackend:
    name = "base"

    def snapshot(self):
        """Return the list of USB mass-storage devices currently attached."""
        raise NotImplementedError


def normalize_device(raw):
    """Fill in missing keys so every consumer gets the same shape."""
    mounts = raw.get("mounts") or []
    return {
        "device_id": str(raw["device_id"]),
        "name": raw.get("name") or "Unknown USB device",
        "vendor_id": (raw.get("vendor_id") or None) and str(raw["vendor_id"]).upper(),
        "product_id": (raw.get("product_id") or None) and str(raw["product_id"]).upper(),
        "serial_number": raw.get("serial_number") or None,
        "mounts": [str(m) for m in mounts],
        "volume_label": raw.get("volume_label") or None,
        "filesystem": raw.get("filesystem") or None,
        "size_bytes": raw.get("size_bytes"),
    }
