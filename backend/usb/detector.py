"""Explainable BadUSB and Impersonation Detection Engine."""
from __future__ import annotations

import re
from typing import List, Tuple

from .config import (
    KNOWN_EXPLOIT_VID_PID,
    KNOWN_VENDORS,
    RISK_THRESHOLD_CRITICAL,
    RISK_THRESHOLD_SUSPICIOUS,
    RULE_WEIGHTS,
    SHORT_LIVED_HID_THRESHOLD_SECONDS,
    SUSPICIOUS_SERIAL_PATTERNS,
)
from .models import (
    BadUsbAlert,
    DeviceFingerprint,
    DeviceStatus,
    FingerprintCheck,
    Severity,
    TrustStatus,
    UsbDevice,
)


class BadUsbDetector:
    """Rule-based detection engine that evaluates USB devices for impersonation,
    unexpected HID interfaces, bogus descriptors, and exploit hardware signatures.
    """

    def __init__(self):
        self.rules = RULE_WEIGHTS

    def evaluate_device(
        self,
        dev: UsbDevice,
        duration_seconds: float = 0.0,
        historical_seen: bool = False,
    ) -> tuple[int, DeviceStatus, list[FingerprintCheck], list[BadUsbAlert], str]:
        """Evaluates a device and returns:
        (risk_score, status, checks, alerts, notes)
        """
        risk_score = 0
        alerts: list[BadUsbAlert] = []
        notes_list: list[str] = []

        vid = dev.vendor_id.upper() if dev.vendor_id else "0000"
        pid = dev.product_id.upper() if dev.product_id else "0000"
        fp = dev.fingerprint
        interfaces = fp.interfaces or []
        mfg = fp.manufacturer or ""
        prod = fp.product or dev.name or ""
        serial = (dev.serial_number or "").strip()

        # -------------------------------------------------------------
        # Check 1: VID/PID vendor registration
        # -------------------------------------------------------------
        known_vendor_name = KNOWN_VENDORS.get(vid)
        vid_pid_registered = known_vendor_name is not None
        check_1 = FingerprintCheck(
            label="VID/PID registered to claimed vendor",
            pass_check=vid_pid_registered,
            details=f"Vendor {known_vendor_name or 'Unregistered Vendor'} (VID: {vid})",
        )

        # -------------------------------------------------------------
        # Check 2: Manufacturer string matches vendor
        # -------------------------------------------------------------
        mfg_matches_vendor = True
        if known_vendor_name:
            # If vendor is SanDisk but manufacturer says "Generic" or "Arduino"
            if known_vendor_name.lower() not in mfg.lower():
                if any(bad in mfg.lower() for bad in ["generic", "teensy", "arduino", "unknown", "atmel", "null"]):
                    mfg_matches_vendor = False
                    risk_score += self.rules["VENDOR_MISMATCH"]
                    notes_list.append(
                        f"VID {vid} is registered to {known_vendor_name}, but manufacturer string claims '{mfg}'. Potential vendor impersonation."
                    )
        check_2 = FingerprintCheck(
            label="Manufacturer string matches vendor",
            pass_check=mfg_matches_vendor,
            details=f"Claimed '{mfg}', expected '{known_vendor_name or 'N/A'}'",
        )

        # -------------------------------------------------------------
        # Check 3: Serial number format validity
        # -------------------------------------------------------------
        serial_valid = True
        is_storage = "storage" in dev.device_class.lower() or any("storage" in i.lower() for i in interfaces)
        if not serial or serial.upper() in SUSPICIOUS_SERIAL_PATTERNS or re.match(r"^0+$", serial):
            if is_storage:
                serial_valid = False
                risk_score += self.rules["BOGUS_SERIAL"]
                notes_list.append(
                    f"Serial number '{serial or 'N/A'}' matches a known placeholder or bogus pattern for removable storage."
                )
        check_3 = FingerprintCheck(
            label="Serial number format valid",
            pass_check=serial_valid,
            details=f"Serial: '{serial}'",
        )

        # -------------------------------------------------------------
        # Check 4: Interface set matches device class (BadUSB core rule!)
        # -------------------------------------------------------------
        has_keyboard = any("keyboard" in i.lower() for i in interfaces)
        has_mouse = any("mouse" in i.lower() for i in interfaces)
        has_storage = any("storage" in i.lower() for i in interfaces) or "storage" in dev.device_class.lower()

        interface_matches = True
        if has_storage and has_keyboard:
            # Massive red flag: Storage stick exposing a keyboard endpoint!
            interface_matches = False
            risk_score += self.rules["KEYBOARD_ON_STORAGE"]
            notes_list.append(
                "Unexpected HID Keyboard interface exposed by mass-storage device. Typical signature of a BadUSB / Rubber Ducky keystroke injector."
            )
            alerts.append(
                BadUsbAlert(
                    id=f"alt-{dev.id}-hid-storage",
                    device_id=dev.id,
                    vendor_id=vid,
                    product_id=pid,
                    timestamp=dev.connected_at,
                    severity=Severity.CRITICAL.value,
                    risk_score=risk_score,
                    rule="UNEXPECTED_HID_KEYBOARD_ON_STORAGE",
                    reason="Mass storage device exposes an unauthorized HID keyboard interface capable of injecting keystrokes.",
                    recommended_action="Isolate host from network, immediately unplug device, and inspect system autorun, PowerShell history, and terminal logs.",
                )
            )

        check_4 = FingerprintCheck(
            label="Interface set matches device class",
            pass_check=interface_matches,
            details=", ".join(interfaces) if interfaces else dev.device_class,
        )

        # -------------------------------------------------------------
        # Check 5: Known hardware exploitation signatures
        # -------------------------------------------------------------
        exploit_tool_name = KNOWN_EXPLOIT_VID_PID.get((vid, pid))
        if exploit_tool_name:
            risk_score += self.rules["KNOWN_EXPLOIT_HARDWARE"]
            notes_list.append(f"Hardware VID:PID matches known attack hardware: {exploit_tool_name}.")
            alerts.append(
                BadUsbAlert(
                    id=f"alt-{dev.id}-exploit-hw",
                    device_id=dev.id,
                    vendor_id=vid,
                    product_id=pid,
                    timestamp=dev.connected_at,
                    severity=Severity.CRITICAL.value,
                    risk_score=risk_score,
                    rule="KNOWN_EXPLOIT_HARDWARE_SIGNATURE",
                    reason=f"Device hardware ID matches known keystroke injection platform: {exploit_tool_name}.",
                    recommended_action="Unplug device immediately and prevent reconnection. Run a forensic memory audit on the host.",
                )
            )

        # -------------------------------------------------------------
        # Check 6: Short-lived HID injection connection
        # -------------------------------------------------------------
        if (has_keyboard or "hid" in dev.device_class.lower()) and 0 < duration_seconds <= SHORT_LIVED_HID_THRESHOLD_SECONDS:
            if not historical_seen and dev.trust_status != TrustStatus.TRUSTED.value:
                risk_score += self.rules["SHORT_LIVED_HID"]
                notes_list.append(
                    f"HID device connected for only {duration_seconds:.1f}s before disconnecting. Consistent with scripted keystroke payload injection."
                )
                alerts.append(
                    BadUsbAlert(
                        id=f"alt-{dev.id}-short-hid",
                        device_id=dev.id,
                        vendor_id=vid,
                        product_id=pid,
                        timestamp=dev.connected_at,
                        severity=Severity.HIGH.value,
                        risk_score=risk_score,
                        rule="SHORT_LIVED_HID_INJECTION",
                        reason=f"HID peripheral disconnected after {duration_seconds:.1f}s without user typing session, typical of automated payload injection.",
                        recommended_action="Check recent command line history (cmd / PowerShell / bash) and inspect active processes.",
                    )
                )

        # -------------------------------------------------------------
        # Check 7: Seen on host before
        # -------------------------------------------------------------
        check_5 = FingerprintCheck(
            label="Seen on this host before",
            pass_check=historical_seen or dev.seen_count > 1,
            details=f"Seen {dev.seen_count} time(s) previously",
        )

        checks = [check_1, check_2, check_3, check_4, check_5]

        # Clamp risk score
        risk_score = min(100, max(0, risk_score))

        # Determine status
        if risk_score >= RISK_THRESHOLD_CRITICAL:
            status = DeviceStatus.CRITICAL.value
        elif risk_score >= RISK_THRESHOLD_SUSPICIOUS or not mfg_matches_vendor or not interface_matches:
            status = DeviceStatus.SUSPICIOUS.value
        else:
            status = DeviceStatus.SAFE.value

        # Trust override: trusted devices cannot be flagged critical on minor checks
        if dev.trust_status == TrustStatus.TRUSTED.value and not exploit_tool_name and not (has_storage and has_keyboard):
            status = DeviceStatus.SAFE.value
            risk_score = max(0, risk_score - 30)

        # Final notes synthesis
        if not notes_list:
            if status == DeviceStatus.SAFE.value:
                final_notes = f"Known peripheral. Hardware identifiers match genuine {known_vendor_name or prod} device."
            else:
                final_notes = "Unverified device. No specific anomalies flagged, but device is not registered in the trusted peripheral list."
        else:
            final_notes = " ".join(notes_list)

        return risk_score, DeviceStatus(status), checks, alerts, final_notes
