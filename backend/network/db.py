"""SQLite persistence layer.

Schema (see the project brief):

* ``network_events``  - one row per notable flow, matches the /events contract.
* ``connections``     - aggregated flows (every flushed flow).
* ``traffic_stats``   - per-interval outbound/inbound/suspicious bytes.
* ``alerts``          - detector findings.
* ``capture_sessions``- start/stop bookkeeping for the correlation engine.

All statements are parameterized; no value is ever interpolated into SQL.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Optional

from . import config
from .timeutil import add_seconds, parse_iso, to_iso_utc

SCHEMA = """
CREATE TABLE IF NOT EXISTS network_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT    NOT NULL,             -- ISO 8601 UTC
    source_ip         TEXT    NOT NULL,
    destination_ip    TEXT    NOT NULL,
    destination_host  TEXT,
    protocol          TEXT    NOT NULL,
    port              INTEGER,
    packet_size_bytes INTEGER NOT NULL DEFAULT 0,
    direction         TEXT    NOT NULL,             -- OUTBOUND | INBOUND | INTERNAL
    risk              TEXT    NOT NULL,             -- LOW | MEDIUM | HIGH
    usb_session       TEXT                          -- NULL until correlation sets it
);

CREATE TABLE IF NOT EXISTS connections (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip     TEXT    NOT NULL,
    src_port   INTEGER,
    dst_ip     TEXT    NOT NULL,
    dst_port   INTEGER,
    protocol   TEXT    NOT NULL,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    packets    INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_stats (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp          TEXT    NOT NULL,
    bytes_out          INTEGER NOT NULL DEFAULT 0,
    bytes_in           INTEGER NOT NULL DEFAULT 0,
    suspicious_bytes   INTEGER NOT NULL DEFAULT 0,
    packets            INTEGER NOT NULL DEFAULT 0,
    active_connections INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT    NOT NULL,
    dst_ip    TEXT,
    dst_port  INTEGER,
    reason    TEXT    NOT NULL,
    severity  TEXT    NOT NULL,             -- low | medium | high
    bytes     INTEGER NOT NULL DEFAULT 0,
    zscore    REAL,
    event_id  INTEGER
);

CREATE TABLE IF NOT EXISTS capture_sessions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT    NOT NULL,
    ended_at       TEXT,
    trigger        TEXT,
    usb_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON network_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_usb       ON network_events(usb_session);
CREATE INDEX IF NOT EXISTS idx_conn_last_seen   ON connections(last_seen);
CREATE INDEX IF NOT EXISTS idx_stats_ts         ON traffic_stats(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON capture_sessions(started_at);
"""


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open (creating if needed) a SQLite connection with row access by name."""
    path = db_path or config.get_db_path()
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db(conn: Optional[sqlite3.Connection] = None, db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create tables and indexes.  Returns the connection used."""
    owns = conn is None
    if conn is None:
        conn = get_connection(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    if owns:
        # Caller did not pass a connection, so hand back an open one for reuse.
        return conn
    return conn


# --------------------------------------------------------------------------
# Inserts
# --------------------------------------------------------------------------
def insert_event(
    conn: sqlite3.Connection,
    *,
    timestamp: str,
    source_ip: str,
    destination_ip: str,
    destination_host: Optional[str],
    protocol: str,
    port: Optional[int],
    packet_size_bytes: int,
    direction: str,
    risk: str,
    usb_session: Optional[str] = None,
) -> int:
    """Insert a network event and return its row id."""
    cur = conn.execute(
        """
        INSERT INTO network_events
            (timestamp, source_ip, destination_ip, destination_host, protocol,
             port, packet_size_bytes, direction, risk, usb_session)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            source_ip,
            destination_ip,
            destination_host,
            protocol,
            port,
            int(packet_size_bytes),
            direction,
            risk,
            usb_session,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def insert_connection(
    conn: sqlite3.Connection,
    *,
    src_ip: str,
    src_port: Optional[int],
    dst_ip: str,
    dst_port: Optional[int],
    protocol: str,
    bytes_out: int,
    bytes_in: int,
    packets: int,
    first_seen: str,
    last_seen: str,
) -> int:
    """Insert an aggregated flow."""
    cur = conn.execute(
        """
        INSERT INTO connections
            (src_ip, src_port, dst_ip, dst_port, protocol, bytes_out, bytes_in,
             packets, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (src_ip, src_port, dst_ip, dst_port, protocol, int(bytes_out), int(bytes_in), int(packets), first_seen, last_seen),
    )
    conn.commit()
    return int(cur.lastrowid)


def insert_traffic_stat(
    conn: sqlite3.Connection,
    *,
    timestamp: str,
    bytes_out: int,
    bytes_in: int,
    suspicious_bytes: int,
    packets: int,
    active_connections: int,
) -> int:
    """Insert one interval of aggregate traffic."""
    cur = conn.execute(
        """
        INSERT INTO traffic_stats
            (timestamp, bytes_out, bytes_in, suspicious_bytes, packets, active_connections)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, int(bytes_out), int(bytes_in), int(suspicious_bytes), int(packets), int(active_connections)),
    )
    conn.commit()
    return int(cur.lastrowid)


def insert_alert(
    conn: sqlite3.Connection,
    *,
    timestamp: str,
    dst_ip: Optional[str],
    dst_port: Optional[int],
    reason: str,
    severity: str,
    bytes: int,
    zscore: Optional[float] = None,
    event_id: Optional[int] = None,
) -> int:
    """Insert a detector alert."""
    cur = conn.execute(
        """
        INSERT INTO alerts (timestamp, dst_ip, dst_port, reason, severity, bytes, zscore, event_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (timestamp, dst_ip, dst_port, reason, severity, int(bytes), zscore, event_id),
    )
    conn.commit()
    return int(cur.lastrowid)


def insert_capture_session(
    conn: sqlite3.Connection,
    *,
    started_at: str,
    trigger: Optional[str],
    usb_session_id: Optional[str],
) -> int:
    """Open a capture session row."""
    cur = conn.execute(
        "INSERT INTO capture_sessions (started_at, trigger, usb_session_id) VALUES (?, ?, ?)",
        (started_at, trigger, usb_session_id),
    )
    conn.commit()
    return int(cur.lastrowid)


def close_capture_session(conn: sqlite3.Connection, session_id: int, ended_at: str) -> None:
    """Stamp a capture session's ``ended_at``."""
    conn.execute("UPDATE capture_sessions SET ended_at = ? WHERE id = ?", (ended_at, session_id))
    conn.commit()


def tag_events_with_usb_session(conn: sqlite3.Connection, start: str, end: str, usb_session: Optional[str]) -> int:
    """Set ``usb_session`` on events in ``[start, end]``.

    Convenience hook for the correlation engine; ``usb_session`` may be ``None``
    to clear the tag.  Returns the number of rows touched.
    """
    cur = conn.execute(
        "UPDATE network_events SET usb_session = ? WHERE timestamp >= ? AND timestamp <= ?",
        (usb_session, start, end),
    )
    conn.commit()
    return cur.rowcount


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------
def _range_sql(column: str, start: Optional[str], end: Optional[str]) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if start:
        clauses.append(f"{column} >= ?")
        params.append(start)
    if end:
        clauses.append(f"{column} <= ?")
        params.append(end)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def fetch_events(
    conn: sqlite3.Connection,
    start: Optional[str] = None,
    end: Optional[str] = None,
    limit: Optional[int] = None,
) -> list[sqlite3.Row]:
    """Return network events, newest last, optionally filtered by time window."""
    where, params = _range_sql("timestamp", start, end)
    sql = f"SELECT * FROM network_events{where} ORDER BY timestamp DESC, id DESC"
    if limit:
        sql += " LIMIT ?"
        params.append(int(limit))
    return list(conn.execute(sql, params).fetchall())


def fetch_connections(
    conn: sqlite3.Connection,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> list[sqlite3.Row]:
    """Return aggregated flows whose activity overlaps the window."""
    clauses: list[str] = []
    params: list[Any] = []
    if start:
        clauses.append("last_seen >= ?")
        params.append(start)
    if end:
        clauses.append("first_seen <= ?")
        params.append(end)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM connections{where} ORDER BY last_seen ASC, id ASC"
    return list(conn.execute(sql, params).fetchall())


def fetch_alerts(
    conn: sqlite3.Connection,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> list[sqlite3.Row]:
    """Return alerts within the window."""
    where, params = _range_sql("timestamp", start, end)
    sql = f"SELECT * FROM alerts{where} ORDER BY timestamp ASC, id ASC"
    return list(conn.execute(sql, params).fetchall())


def fetch_traffic_stats(
    conn: sqlite3.Connection,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> list[sqlite3.Row]:
    """Return per-interval traffic rows within the window."""
    where, params = _range_sql("timestamp", start, end)
    sql = f"SELECT * FROM traffic_stats{where} ORDER BY timestamp ASC, id ASC"
    return list(conn.execute(sql, params).fetchall())


def fetch_stats_summary(conn: sqlite3.Connection) -> dict[str, int]:
    """Compute the four numbers backing the /network/stats endpoint.

    ``activeConnections`` is measured against the newest observed activity rather
    than wall-clock now, so historical/demo data still reports sensibly.
    """
    packets = conn.execute("SELECT COALESCE(SUM(packets), 0) AS v FROM traffic_stats").fetchone()["v"]
    out_bytes = conn.execute("SELECT COALESCE(SUM(bytes_out), 0) AS v FROM traffic_stats").fetchone()["v"]

    # Fall back to the flow table per-metric when aggregates are missing/empty.
    if packets == 0:
        packets = conn.execute("SELECT COALESCE(SUM(packets), 0) AS v FROM connections").fetchone()["v"]
    if out_bytes == 0:
        out_bytes = conn.execute("SELECT COALESCE(SUM(bytes_out), 0) AS v FROM connections").fetchone()["v"]

    row = conn.execute("SELECT MAX(last_seen) AS v FROM connections").fetchone()
    newest = row["v"] if row else None
    if newest:
        # Timestamps share one canonical fixed-width UTC format, so a plain
        # string comparison is exact (and avoids SQLite's Z-suffix parsing quirks).
        cutoff = to_iso_utc(add_seconds(parse_iso(newest), -config.ACTIVE_CONNECTION_WINDOW_SECONDS))
        active = conn.execute(
            "SELECT COUNT(*) AS v FROM connections WHERE last_seen >= ?",
            (cutoff,),
        ).fetchone()["v"]
    else:
        active = 0

    suspicious = conn.execute(
        "SELECT COUNT(DISTINCT dst_ip) AS v FROM alerts WHERE severity IN ('medium', 'high') AND dst_ip IS NOT NULL"
    ).fetchone()["v"]

    return {
        "packetsCaptured": int(packets),
        "outboundBytes": int(out_bytes),
        "activeConnections": int(active),
        "suspiciousConnections": int(suspicious),
    }


def clear_all(conn: sqlite3.Connection) -> None:
    """Delete every row (test/demo helper)."""
    for table in ("network_events", "connections", "traffic_stats", "alerts", "capture_sessions"):
        conn.execute(f"DELETE FROM {table}")  # noqa: S608 - table name from fixed list
    conn.commit()
