"""Convert SQLite rows into the exact JSON shapes the frontend expects.

The frontend contract lives in ``src/data/mockData.js`` (keys ``mockNetworkEvents``,
``mockNetworkStats``, ``mockTrafficSeries``).  Keeping every camelCase conversion
here means that if the frontend changes, only this file needs editing.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from . import config
from .timeutil import bucket_label, bucket_start, parse_iso


def format_event_id(row_id: int) -> str:
    """Render a DB id as the frontend's ``'n-01'`` style."""
    return f"n-{int(row_id):02d}"


def _get(row: Mapping[str, Any], key: str, default: Any = None) -> Any:
    """Read from a sqlite3.Row or dict."""
    try:
        value = row[key]
    except (KeyError, IndexError):
        return default
    return default if value is None else value


def event_to_api(row: Mapping[str, Any]) -> dict[str, Any]:
    """network_events row -> /network/events item (exact mock field names)."""
    return {
        "id": format_event_id(_get(row, "id")),
        "timestamp": _get(row, "timestamp"),
        "sourceIp": _get(row, "source_ip"),
        "destinationIp": _get(row, "destination_ip"),
        "destinationHost": _get(row, "destination_host") or _get(row, "destination_ip"),
        "protocol": _get(row, "protocol"),
        "port": _get(row, "port"),
        "packetSizeBytes": int(_get(row, "packet_size_bytes", 0) or 0),
        "direction": _get(row, "direction"),
        "risk": _get(row, "risk"),
        "usbSession": _get(row, "usb_session"),  # None == JSON null
    }


def stats_to_api(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Summary dict -> /network/stats object."""
    return {
        "packetsCaptured": int(summary.get("packetsCaptured", 0)),
        "outboundBytes": int(summary.get("outboundBytes", 0)),
        "activeConnections": int(summary.get("activeConnections", 0)),
        "suspiciousConnections": int(summary.get("suspiciousConnections", 0)),
    }


def connection_to_api(row: Mapping[str, Any]) -> dict[str, Any]:
    """connections row -> correlation-friendly dict (not a frontend endpoint)."""
    return {
        "id": int(_get(row, "id", 0)),
        "srcIp": _get(row, "src_ip"),
        "srcPort": _get(row, "src_port"),
        "dstIp": _get(row, "dst_ip"),
        "dstPort": _get(row, "dst_port"),
        "protocol": _get(row, "protocol"),
        "bytesOut": int(_get(row, "bytes_out", 0) or 0),
        "bytesIn": int(_get(row, "bytes_in", 0) or 0),
        "packets": int(_get(row, "packets", 0) or 0),
        "firstSeen": _get(row, "first_seen"),
        "lastSeen": _get(row, "last_seen"),
    }


def alert_to_api(row: Mapping[str, Any]) -> dict[str, Any]:
    """alerts row -> correlation-friendly dict."""
    return {
        "id": int(_get(row, "id", 0)),
        "timestamp": _get(row, "timestamp"),
        "dstIp": _get(row, "dst_ip"),
        "dstPort": _get(row, "dst_port"),
        "reason": _get(row, "reason"),
        "severity": _get(row, "severity"),
        "risk": severity_to_risk(_get(row, "severity")),
        "bytes": int(_get(row, "bytes", 0) or 0),
        "zscore": _get(row, "zscore"),
        "eventId": _get(row, "event_id"),
    }


def severity_to_risk(severity: Optional[str]) -> Optional[str]:
    """Map detector severity (lowercase) to the frontend risk field (uppercase)."""
    if not severity:
        return None
    return {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}.get(str(severity).lower(), str(severity).upper())


def traffic_to_api(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """traffic_stats rows -> /network/traffic array of 30-minute buckets.

    Multiple raw intervals are summed into one bucket and converted to MB, with a
    single decimal place to match the mock (e.g. ``1.2``).
    """
    buckets: dict[str, dict[str, float]] = {}
    order: list[str] = []

    for row in rows:
        ts = _get(row, "timestamp")
        dt = parse_iso(ts)
        if dt is None:
            continue
        start = bucket_start(dt, config.TRAFFIC_BUCKET_SECONDS)
        label = bucket_label(start)
        if label not in buckets:
            buckets[label] = {"outbound": 0.0, "inbound": 0.0, "suspicious": 0.0}
            order.append(label)
        buckets[label]["outbound"] += float(_get(row, "bytes_out", 0) or 0) / 1_000_000
        buckets[label]["inbound"] += float(_get(row, "bytes_in", 0) or 0) / 1_000_000
        buckets[label]["suspicious"] += float(_get(row, "suspicious_bytes", 0) or 0) / 1_000_000

    return [
        {
            "time": label,
            "outbound": round(buckets[label]["outbound"], 1),
            "inbound": round(buckets[label]["inbound"], 1),
            "suspicious": round(buckets[label]["suspicious"], 1),
        }
        for label in order
    ]
