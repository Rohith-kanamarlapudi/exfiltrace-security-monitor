"""Data models for USB Forensics, Fingerprints, and BadUSB Alerts."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional


class TrustStatus(str, Enum):
    TRUSTED = "TRUSTED"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"


class DeviceStatus(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class FingerprintCheck:
    label: str
    pass_check: bool
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "pass": self.pass_check,
            "details": self.details,
        }


@dataclass
class DeviceFingerprint:
    manufacturer: str = "Unknown"
    product: str = "Unknown"
    usb_version: str = "2.00"
    bcd_device: str = "1.00"
    max_power: str = "100 mA"
    interfaces: list[str] = field(default_factory=list)
    descriptor_hash: str = ""
    checks: list[FingerprintCheck] = field(default_factory=list)
    notes: str = ""

    def compute_hash(self, vid: str, pid: str, serial: str) -> str:
        payload = f"{vid}:{pid}:{self.manufacturer}:{self.product}:{self.usb_version}:{self.bcd_device}:{serial}:{','.join(sorted(self.interfaces))}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        self.descriptor_hash = digest
        return digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "manufacturer": self.manufacturer,
            "product": self.product,
            "usbVersion": self.usb_version,
            "bcdDevice": self.bcd_device,
            "maxPower": self.max_power,
            "interfaces": self.interfaces,
            "descriptorHash": self.descriptor_hash,
            "checks": [c.to_dict() for c in self.checks],
            "notes": self.notes,
        }


@dataclass
class BadUsbAlert:
    id: str
    device_id: str
    vendor_id: str
    product_id: str
    timestamp: str
    severity: str
    risk_score: int
    rule: str
    reason: str
    recommended_action: str
    acknowledged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "deviceId": self.device_id,
            "vendorId": self.vendor_id,
            "productId": self.product_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "riskScore": self.risk_score,
            "rule": self.rule,
            "reason": self.reason,
            "recommendedAction": self.recommended_action,
            "acknowledged": self.acknowledged,
        }


@dataclass
class UsbDevice:
    id: str
    name: str
    vendor_id: str
    product_id: str
    serial_number: str
    device_class: str
    connected_at: str
    disconnected_at: Optional[str] = None
    status: str = DeviceStatus.SAFE.value
    trust_status: str = TrustStatus.UNKNOWN.value
    session: str = "USB-S-0001"
    risk_score: int = 0
    mounts: list[str] = field(default_factory=list)
    fingerprint: DeviceFingerprint = field(default_factory=DeviceFingerprint)
    seen_count: int = 1
    total_connected_seconds: int = 0

    def to_api(self) -> dict[str, Any]:
        """Matches src/data/mockData.js mockUsbDevices shape exactly."""
        return {
            "id": self.id,
            "name": self.name,
            "vendorId": self.vendor_id,
            "productId": self.product_id,
            "serialNumber": self.serial_number,
            "deviceClass": self.device_class,
            "connectedAt": self.connected_at,
            "disconnectedAt": self.disconnected_at,
            "status": self.status,
            "trustStatus": self.trust_status,
            "session": self.session,
            "riskScore": self.risk_score,
            "mounts": self.mounts,
            "seenCount": self.seen_count,
            "fingerprint": self.fingerprint.to_dict(),
        }
