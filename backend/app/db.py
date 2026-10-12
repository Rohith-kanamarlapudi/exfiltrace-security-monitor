"""SQLite storage. One small file DB; each call opens its own short-lived connection (thread safe)."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,            -- CREATED | MODIFIED | DELETED | RENAMED
    path TEXT NOT NULL,
    dest_path TEXT,                      -- new path for RENAMED
    file_name TEXT NOT NULL,
    extension TEXT,
    size_bytes INTEGER,
    sensitive INTEGER NOT NULL DEFAULT 0,
    sensitivity_reason TEXT,
    on_removable INTEGER NOT NULL DEFAULT 0,
    volume TEXT,                         -- removable mount the file is on, if any
    usb_device_id TEXT,
    risk TEXT NOT NULL DEFAULT 'LOW',    -- LOW | MEDIUM | HIGH
    details TEXT                         -- JSON
);
CREATE INDEX IF NOT EXISTS idx_file_ts ON file_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_file_path ON file_events(path);

CREATE TABLE IF NOT EXISTS usb_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,            -- INSERTED | REMOVED
    device_id TEXT NOT NULL,
    name TEXT,
    vendor_id TEXT,
    product_id TEXT,
    serial_number TEXT,
    mounts TEXT,                         -- JSON list of drive letters / mount points
    volume_label TEXT,
    filesystem TEXT,
    size_bytes INTEGER,
    details TEXT                         -- JSON
);
CREATE INDEX IF NOT EXISTS idx_usb_ts ON usb_events(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,              -- LOW | MEDIUM | HIGH | CRITICAL
    verdict TEXT NOT NULL,               -- SUSPICIOUS | VERIFIED_TRANSFER
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence TEXT,                       -- JSON list of strings
    file_event_ids TEXT,                 -- JSON list
    usb_event_ids TEXT,                  -- JSON list
    dedupe_key TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_alert_ts ON alerts(timestamp);
"""

_JSON_COLUMNS = {"details", "mounts", "evidence", "file_event_ids", "usb_event_ids"}


def now_iso():
    """Local wall-clock time, ISO 8601 with offset, second precision + millis."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")


class Database:
    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.init()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self):
        with self.connect() as conn:
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
            conn.executescript(SCHEMA)

    # ---------- helpers ----------
    @staticmethod
    def _row(row):
        d = dict(row)
        for col in _JSON_COLUMNS:
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except json.JSONDecodeError:
                    pass
        for col in ("sensitive", "on_removable"):
            if col in d:
                d[col] = bool(d[col])
        return d

    def _insert(self, table, values):
        values = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in values.items()}
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        with self.connect() as conn:
            cur = conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(values.values()))
            return cur.lastrowid

    def _get(self, table, row_id):
        with self.connect() as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (row_id,)).fetchone()
        return self._row(row) if row else None

    # ---------- file events ----------
    def add_file_event(self, **v):
        v.setdefault("timestamp", now_iso())
        return self._get("file_events", self._insert("file_events", v))

    def update_file_event_size(self, event_id, size_bytes):
        with self.connect() as conn:
            conn.execute("UPDATE file_events SET size_bytes = ? WHERE id = ?", (size_bytes, event_id))

    def query_file_events(self, event_type=None, sensitive=None, removable=None, search=None,
                          since=None, until=None, limit=200, offset=0):
        where, args = [], []
        if event_type:
            where.append("event_type = ?"); args.append(event_type.upper())
        if sensitive is not None:
            where.append("sensitive = ?"); args.append(1 if sensitive else 0)
        if removable is not None:
            where.append("on_removable = ?"); args.append(1 if removable else 0)
        if search:
            where.append("(path LIKE ? OR dest_path LIKE ? OR file_name LIKE ?)")
            like = f"%{search}%"; args += [like, like, like]
        if since:
            where.append("timestamp >= ?"); args.append(since)
        if until:
            where.append("timestamp <= ?"); args.append(until)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM file_events {clause}", args).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM file_events {clause} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                args + [int(limit), int(offset)],
            ).fetchall()
        return [self._row(r) for r in rows], total

    def file_stats(self):
        with self.connect() as conn:
            q = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
            return {
                "total_events": q("SELECT COUNT(*) FROM file_events"),
                "sensitive_events": q("SELECT COUNT(*) FROM file_events WHERE sensitive = 1"),
                "removable_events": q("SELECT COUNT(*) FROM file_events WHERE on_removable = 1"),
                "high_risk_events": q("SELECT COUNT(*) FROM file_events WHERE risk = 'HIGH'"),
                "sensitive_files": q("SELECT COUNT(DISTINCT COALESCE(dest_path, path)) FROM file_events WHERE sensitive = 1"),
            }

    def sensitive_files(self, limit=100):
        """Latest event per sensitive path."""
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT * FROM file_events WHERE sensitive = 1 AND id IN
                   (SELECT MAX(id) FROM file_events WHERE sensitive = 1 GROUP BY path)
                   ORDER BY timestamp DESC LIMIT ?""", (int(limit),)).fetchall()
        return [self._row(r) for r in rows]

    def recent_file_events(self, since_iso, sensitive_only=False):
        sql = "SELECT * FROM file_events WHERE timestamp >= ?"
        if sensitive_only:
            sql += " AND sensitive = 1"
        with self.connect() as conn:
            rows = conn.execute(sql + " ORDER BY timestamp ASC, id ASC", (since_iso,)).fetchall()
        return [self._row(r) for r in rows]

    # ---------- usb events ----------
    def add_usb_event(self, **v):
        v.setdefault("timestamp", now_iso())
        return self._get("usb_events", self._insert("usb_events", v))

    def query_usb_events(self, event_type=None, search=None, limit=200, offset=0):
        where, args = [], []
        if event_type:
            where.append("event_type = ?"); args.append(event_type.upper())
        if search:
            where.append("(name LIKE ? OR device_id LIKE ? OR serial_number LIKE ? OR vendor_id LIKE ? OR product_id LIKE ?)")
            like = f"%{search}%"; args += [like] * 5
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM usb_events {clause}", args).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM usb_events {clause} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                args + [int(limit), int(offset)]).fetchall()
        return [self._row(r) for r in rows], total

    def usb_events_since(self, since_iso):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM usb_events WHERE timestamp >= ? ORDER BY timestamp ASC, id ASC",
                                (since_iso,)).fetchall()
        return [self._row(r) for r in rows]

    def last_insert_event(self, device_id):
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM usb_events WHERE device_id = ? AND event_type = 'INSERTED' ORDER BY id DESC LIMIT 1",
                (device_id,)).fetchone()
        return self._row(row) if row else None

    # ---------- alerts ----------
    def add_alert(self, **v):
        """Returns the alert row, or None when an alert with the same dedupe_key already exists."""
        v.setdefault("timestamp", now_iso())
        try:
            return self._get("alerts", self._insert("alerts", v))
        except sqlite3.IntegrityError:
            return None

    def query_alerts(self, severity=None, verdict=None, limit=200, offset=0):
        where, args = [], []
        if severity:
            where.append("severity = ?"); args.append(severity.upper())
        if verdict:
            where.append("verdict = ?"); args.append(verdict.upper())
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.connect() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM alerts {clause}", args).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM alerts {clause} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                args + [int(limit), int(offset)]).fetchall()
        return [self._row(r) for r in rows], total

    def alert_count(self):
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
