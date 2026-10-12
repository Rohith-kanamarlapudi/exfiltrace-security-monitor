"""Forensics service orchestrating device discovery, BadUSB detection, and persistence."""
from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional

from .config import DEFAULT_DB_PATH, POLL_INTERVAL_SECONDS
from .db import UsbForensicsDb, utc_now_iso
from .detector import BadUsbDetector
from .models import BadUsbAlert, DeviceStatus, TrustStatus, UsbDevice
from .simulator import get_scenario_devices
from .windows_pnp import query_windows_usb_devices

log = logging.getLogger("exfiltrace.usb.service")


class UsbForensicsService:
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        enable_real_discovery: bool = True,
        poll_interval: float = POLL_INTERVAL_SECONDS,
    ):
        self.db = UsbForensicsDb(db_path)
        self.detector = BadUsbDetector()
        self.enable_real_discovery = enable_real_discovery
        self.poll_interval = poll_interval

        self._active_devices: dict[str, UsbDevice] = {}
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.running = False
        self.last_scan_time: Optional[str] = None
        self.real_hardware_count = 0
        self.simulated_count = 0

        # Seed with initial baseline scenarios if DB is completely empty
        self._bootstrap_initial_data()

    def _bootstrap_initial_data(self):
        """Seed initial forensics database if completely empty, so UI is never blank on fresh launch."""
        existing = self.db.get_all_devices()
        if not existing:
            log.info("Bootstrapping baseline forensic devices and scenario profiles")
            scenarios = get_scenario_devices()
            for dev in scenarios:
                # Run through detector to populate checks and alerts
                risk, status, checks, alerts, notes = self.detector.evaluate_device(dev)
                dev.risk_score = risk
                dev.status = status.value
                dev.fingerprint.checks = checks
                dev.fingerprint.notes = notes
                self.db.save_device(dev)
                for alert in alerts:
                    self.db.add_alert(alert)
                self._active_devices[dev.id] = dev
            self.simulated_count = len(scenarios)

    def scan_once(self) -> list[UsbDevice]:
        """Perform one discovery and forensic evaluation cycle."""
        with self._lock:
            real_devices = []
            if self.enable_real_discovery:
                try:
                    real_devices = query_windows_usb_devices()
                except Exception as exc:
                    log.warning("Real hardware scan failed: %s", exc)

            self.real_hardware_count = len(real_devices)
            now_iso = utc_now_iso()
            self.last_scan_time = now_iso

            for dev in real_devices:
                # Check if device was seen historically
                past = self.db.get_device(dev.id)
                historical_seen = past is not None
                if past:
                    dev.trust_status = past.trust_status
                    dev.seen_count = past.seen_count

                risk, status, checks, alerts, notes = self.detector.evaluate_device(
                    dev, historical_seen=historical_seen
                )
                dev.risk_score = risk
                dev.status = status.value
                dev.fingerprint.checks = checks
                dev.fingerprint.notes = notes

                self.db.save_device(dev)
                for a in alerts:
                    self.db.add_alert(a)
                self._active_devices[dev.id] = dev

            # Return complete active + persistent inventory
            return self.db.get_all_devices()

    def get_all_devices(self, connected_only: bool = False) -> list[UsbDevice]:
        return self.db.get_all_devices(connected_only=connected_only)

    def get_device(self, device_id: str) -> Optional[UsbDevice]:
        return self.db.get_device(device_id)

    def set_device_trust(self, device_id: str, trust_status: str, reason: str = "") -> bool:
        with self._lock:
            success = self.db.set_trust_status(device_id, trust_status, reason)
            if success:
                # Re-evaluate device under new trust classification
                dev = self.db.get_device(device_id)
                if dev:
                    risk, status, checks, _, notes = self.detector.evaluate_device(dev)
                    dev.risk_score = risk
                    dev.status = status.value
                    dev.fingerprint.checks = checks
                    dev.fingerprint.notes = notes
                    self.db.save_device(dev)
                    self._active_devices[dev.id] = dev
            return success

    def get_alerts(self, limit: int = 100, unack_only: bool = False) -> list[BadUsbAlert]:
        return self.db.get_alerts(limit=limit, unack_only=unack_only)

    def acknowledge_alert(self, alert_id: str) -> bool:
        return self.db.acknowledge_alert(alert_id)

    def inject_scenario(self, scenario_name: str) -> Optional[UsbDevice]:
        """Inject a simulated device scenario for repeatable test demonstrations."""
        with self._lock:
            scenarios = {d.id: d for d in get_scenario_devices()}
            name_map = {
                "badusb_sandisk": "usb-003",
                "teensy_injector": "usb-006",
                "legit_logitech": "usb-001",
                "legit_sandisk": "usb-002",
                "unregistered_kingston": "usb-004",
            }
            target_id = name_map.get(scenario_name, scenario_name)
            dev = scenarios.get(target_id)
            if not dev:
                return None

            now = utc_now_iso()
            dev.connected_at = now
            dev.disconnected_at = None
            risk, status, checks, alerts, notes = self.detector.evaluate_device(dev)
            dev.risk_score = risk
            dev.status = status.value
            dev.fingerprint.checks = checks
            dev.fingerprint.notes = notes

            self.db.save_device(dev)
            for a in alerts:
                self.db.add_alert(a)

            self._active_devices[dev.id] = dev
            self.simulated_count += 1
            return dev

    def start(self):
        with self._lock:
            if self.running:
                return
            self.running = True
            self._stop_event.clear()
            # Initial discovery scan
            self.scan_once()
            self._thread = threading.Thread(target=self._loop, name="usb-forensics-worker", daemon=True)
            self._thread.start()
            log.info("USB Forensics service started")

    def _loop(self):
        while not self._stop_event.wait(self.poll_interval):
            try:
                self.scan_once()
            except Exception as exc:
                log.error("USB Forensics poll error: %s", exc)

    def stop(self):
        with self._lock:
            if not self.running:
                return
            self.running = False
            self._stop_event.set()
            if self._thread:
                self._thread.join(timeout=4)
                self._thread = None
            log.info("USB Forensics service stopped")

    def get_status(self) -> dict:
        devices = self.db.get_all_devices()
        connected = [d for d in devices if d.disconnected_at is None]
        suspicious = [d for d in devices if d.status == DeviceStatus.SUSPICIOUS.value]
        critical = [d for d in devices if d.status == DeviceStatus.CRITICAL.value]
        alerts = self.db.get_alerts(limit=50, unack_only=True)

        return {
            "running": self.running,
            "lastScan": self.last_scan_time,
            "totalDevicesSeen": len(devices),
            "connectedDevices": len(connected),
            "suspiciousDevices": len(suspicious),
            "criticalDevices": len(critical),
            "unacknowledgedAlerts": len(alerts),
            "realHardwareDiscovered": self.real_hardware_count,
            "pollIntervalSeconds": self.poll_interval,
        }
