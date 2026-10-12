"""Persistent SQLite database for USB Forensics, Trust, and BadUSB Alerts."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, List, Optional

from .models import BadUsbAlert, DeviceFingerprint, FingerprintCheck, UsbDevice

SCHEMA = """
CREATE TABLE IF NOT EXISTS forensic_devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    vendor_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    serial_number TEXT,
    device_class TEXT NOT NULL,
    connected_at TEXT NOT NULL,
    disconnected_at TEXT,
    status TEXT NOT NULL,
    trust_status TEXT NOT NULL,
    session TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    mounts TEXT,
    fingerprint TEXT,
    seen_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS forensic_alerts (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    vendor_id TEXT,
    product_id TEXT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    rule TEXT NOT NULL,
    reason TEXT NOT NULL,
    recommended_action TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_trust_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_dev_vid_pid ON forensic_devices(vendor_id, product_id);
CREATE INDEX IF NOT EXISTS idx_dev_trust ON forensic_devices(trust_status);
CREATE INDEX IF NOT EXISTS idx_alert_ts ON forensic_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_dev ON forensic_alerts(device_id);
"""


def utc_now_iso() -> str:
    """Canonical ISO 8601 UTC timestamp ending in Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class UsbForensicsDb:
    def __init__(self, db_path: str):
        self.db_path = db_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_db()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self):
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def save_device(self, dev: UsbDevice) -> None:
        """Upsert a forensic device record."""
        now = utc_now_iso()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT seen_count, first_seen, trust_status FROM forensic_devices WHERE id = ?",
                (dev.id,),
            ).fetchone()

            if existing:
                seen_count = existing["seen_count"] + 1 if dev.disconnected_at is None else existing["seen_count"]
                first_seen = existing["first_seen"]
                # Keep user-assigned trust status if already set
                trust_status = existing["trust_status"] or dev.trust_status
            else:
                seen_count = dev.seen_count or 1
                first_seen = dev.connected_at or now
                trust_status = dev.trust_status

            dev.trust_status = trust_status
            dev.seen_count = seen_count

            fp_json = json.dumps(dev.fingerprint.to_dict())
            mounts_json = json.dumps(dev.mounts)

            conn.execute(
                """
                INSERT INTO forensic_devices (
                    id, name, vendor_id, product_id, serial_number, device_class,
                    connected_at, disconnected_at, status, trust_status, session,
                    risk_score, mounts, fingerprint, seen_count, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    connected_at = excluded.connected_at,
                    disconnected_at = excluded.disconnected_at,
                    status = excluded.status,
                    trust_status = excluded.trust_status,
                    session = excluded.session,
                    risk_score = excluded.risk_score,
                    mounts = excluded.mounts,
                    fingerprint = excluded.fingerprint,
                    seen_count = excluded.seen_count,
                    last_seen = excluded.last_seen
                """,
                (
                    dev.id,
                    dev.name,
                    dev.vendor_id,
                    dev.product_id,
                    dev.serial_number,
                    dev.device_class,
                    dev.connected_at,
                    dev.disconnected_at,
                    dev.status,
                    trust_status,
                    dev.session,
                    dev.risk_score,
                    mounts_json,
                    fp_json,
                    seen_count,
                    first_seen,
                    now,
                ),
            )

    def mark_disconnected(self, device_id: str, ts: Optional[str] = None) -> None:
        dis_ts = ts or utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                "UPDATE forensic_devices SET disconnected_at = ?, last_seen = ? WHERE id = ?",
                (dis_ts, dis_ts, device_id),
            )

    def set_trust_status(self, device_id: str, new_status: str, reason: str = "") -> bool:
        new_status = new_status.upper()
        now = utc_now_iso()
        with self.connect() as conn:
            cur = conn.execute("SELECT trust_status FROM forensic_devices WHERE id = ?", (device_id,))
            row = cur.fetchone()
            if not row:
                return False
            old_status = row["trust_status"]
            conn.execute(
                "UPDATE forensic_devices SET trust_status = ? WHERE id = ?",
                (new_status, device_id),
            )
            conn.execute(
                "INSERT INTO device_trust_audit (device_id, old_status, new_status, timestamp, reason) VALUES (?, ?, ?, ?, ?)",
                (device_id, old_status, new_status, now, reason),
            )
            return True

    def get_all_devices(self, connected_only: bool = False) -> list[UsbDevice]:
        query = "SELECT * FROM forensic_devices"
        if connected_only:
            query += " WHERE disconnected_at IS NULL"
        query += " ORDER BY last_seen DESC"

        devices: list[UsbDevice] = []
        with self.connect() as conn:
            for row in conn.execute(query).fetchall():
                devices.append(self._row_to_device(row))
        return devices

    def get_device(self, device_id: str) -> Optional[UsbDevice]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM forensic_devices WHERE id = ?", (device_id,)).fetchone()
            return self._row_to_device(row) if row else None

    def add_alert(self, alert: BadUsbAlert) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO forensic_alerts
                    (id, device_id, vendor_id, product_id, timestamp, severity, risk_score, rule, reason, recommended_action, acknowledged)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.device_id,
                    alert.vendor_id,
                    alert.product_id,
                    alert.timestamp,
                    alert.severity,
                    alert.risk_score,
                    alert.rule,
                    alert.reason,
                    alert.recommended_action,
                    1 if alert.acknowledged else 0,
                ),
            )

    def get_alerts(self, limit: int = 100, unack_only: bool = False) -> list[BadUsbAlert]:
        query = "SELECT * FROM forensic_alerts"
        if unack_only:
            query += " WHERE acknowledged = 0"
        query += " ORDER BY timestamp DESC LIMIT ?"

        alerts: list[BadUsbAlert] = []
        with self.connect() as conn:
            for row in conn.execute(query, (limit,)).fetchall():
                alerts.append(
                    BadUsbAlert(
                        id=row["id"],
                        device_id=row["device_id"],
                        vendor_id=row["vendor_id"],
                        product_id=row["product_id"],
                        timestamp=row["timestamp"],
                        severity=row["severity"],
                        risk_score=row["risk_score"],
                        rule=row["rule"],
                        reason=row["reason"],
                        recommended_action=row["recommended_action"],
                        acknowledged=bool(row["acknowledged"]),
                    )
                )
        return alerts

    def acknowledge_alert(self, alert_id: str) -> bool:
        with self.connect() as conn:
            cur = conn.execute("UPDATE forensic_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
            return cur.rowcount > 0

    def _row_to_device(self, row: sqlite3.Row) -> UsbDevice:
        fp_data = json.loads(row["fingerprint"] or "{}")
        checks = [
            FingerprintCheck(
                label=c.get("label", ""),
                pass_check=c.get("pass", True),
                details=c.get("details", ""),
            )
            for c in fp_data.get("checks", [])
        ]
        fp = DeviceFingerprint(
            manufacturer=fp_data.get("manufacturer", "Unknown"),
            product=fp_data.get("product", "Unknown"),
            usb_version=fp_data.get("usbVersion", "2.00"),
            bcd_device=fp_data.get("bcdDevice", "1.00"),
            max_power=fp_data.get("maxPower", "100 mA"),
            interfaces=fp_data.get("interfaces", []),
            descriptor_hash=fp_data.get("descriptorHash", ""),
            checks=checks,
            notes=fp_data.get("notes", ""),
        )
        mounts = json.loads(row["mounts"] or "[]")
        return UsbDevice(
            id=row["id"],
            name=row["name"],
            vendor_id=row["vendor_id"],
            product_id=row["product_id"],
            serial_number=row["serial_number"] or "N/A",
            device_class=row["device_class"],
            connected_at=row["connected_at"],
            disconnected_at=row["disconnected_at"],
            status=row["status"],
            trust_status=row["trust_status"],
            session=row["session"],
            risk_score=row["risk_score"],
            mounts=mounts,
            fingerprint=fp,
            seen_count=row["seen_count"],
        )
