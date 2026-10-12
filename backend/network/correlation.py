"""Correlation helper for the final Correlation Engine stage.

Import this directly; it needs no Flask app::

    from backend.network.correlation import get_events_in_window

    window = get_events_in_window("2026-10-05T14:02:11Z", "2026-10-05T14:06:41Z")
    # -> {"events": [...], "flows": [...], "alerts": [...]}

``events`` are already in the exact frontend shape; ``flows`` and ``alerts`` are
camelCased for convenience.  Timestamps are ISO 8601 UTC.
"""

from __future__ import annotations

from typing import Any, Optional

from . import db, serializers


def get_events_in_window(
    start: Optional[str],
    end: Optional[str],
    db_path: Optional[str] = None,
) -> dict[str, list[dict[str, Any]]]:
    """Return everything the network module captured inside ``[start, end]``.

    Parameters
    ----------
    start, end:
        ISO 8601 UTC bounds (inclusive).  Pass ``None`` to leave a bound open.
    db_path:
        Optional override of the SQLite path (defaults to ``config.get_db_path()``).

    Returns
    -------
    dict with keys ``events``, ``flows`` and ``alerts``.
    """
    conn = db.get_connection(db_path)
    try:
        events = [serializers.event_to_api(row) for row in db.fetch_events(conn, start=start, end=end)]
        flows = [serializers.connection_to_api(row) for row in db.fetch_connections(conn, start=start, end=end)]
        alerts = [serializers.alert_to_api(row) for row in db.fetch_alerts(conn, start=start, end=end)]
        return {"events": events, "flows": flows, "alerts": alerts}
    finally:
        conn.close()


def tag_usb_session(start: str, end: str, usb_session: Optional[str], db_path: Optional[str] = None) -> int:
    """Stamp ``usb_session`` on every network event in ``[start, end]``.

    Convenience for the correlation engine once it has matched a USB window.
    """
    conn = db.get_connection(db_path)
    try:
        return db.tag_events_with_usb_session(conn, start, end, usb_session)
    finally:
        conn.close()
