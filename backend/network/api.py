"""Flask blueprint exposing the three network endpoints.

The blueprint is registered under ``/api`` by ``app.create_app`` so the routes
below resolve to::

    GET /api/network/events
    GET /api/network/stats
    GET /api/network/traffic

Response shapes match ``src/data/mockData.js`` exactly.  ``events`` and
``traffic`` accept optional ``?start=&end=`` ISO 8601 UTC filters so the
correlation engine can query a single USB-session window.
"""

from __future__ import annotations

from typing import Optional

from flask import Blueprint, jsonify, request

from . import db, serializers

network_bp = Blueprint("network", __name__)


def _query_window() -> tuple[Optional[str], Optional[str]]:
    """Read and normalise ``start`` / ``end`` query parameters."""
    start = request.args.get("start") or None
    end = request.args.get("end") or None
    return start, end


def _bad_range(start: Optional[str], end: Optional[str]) -> bool:
    """Guard against a caller passing end < start (fixed-width ISO strings compare)."""
    return bool(start and end and end < start)


@network_bp.get("/network/events")
def get_network_events():
    """Array of network events matching ``mockNetworkEvents``."""
    start, end = _query_window()
    if _bad_range(start, end):
        return jsonify({"error": "end must be greater than or equal to start"}), 400
    conn = db.get_connection()
    try:
        rows = db.fetch_events(conn, start=start, end=end)
        return jsonify([serializers.event_to_api(row) for row in rows])
    finally:
        conn.close()


@network_bp.get("/network/stats")
def get_network_stats():
    """Object matching ``mockNetworkStats``."""
    conn = db.get_connection()
    try:
        summary = db.fetch_stats_summary(conn)
        return jsonify(serializers.stats_to_api(summary))
    finally:
        conn.close()


@network_bp.get("/network/traffic")
def get_network_traffic():
    """Array of 30-minute buckets matching ``mockTrafficSeries``."""
    start, end = _query_window()
    if _bad_range(start, end):
        return jsonify({"error": "end must be greater than or equal to start"}), 400
    conn = db.get_connection()
    try:
        rows = db.fetch_traffic_stats(conn, start=start, end=end)
        return jsonify(serializers.traffic_to_api(rows))
    finally:
        conn.close()
