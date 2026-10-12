"""Endpoint contract tests: exact field names, types and value casing.

These assert the shapes against ``src/data/mockData.js`` so the frontend can
switch from mocks to the real API without any component changes.
"""

from __future__ import annotations

from backend.network import db

EVENT_KEYS = {
    "id",
    "timestamp",
    "sourceIp",
    "destinationIp",
    "destinationHost",
    "protocol",
    "port",
    "packetSizeBytes",
    "direction",
    "risk",
    "usbSession",
}
STATS_KEYS = {"packetsCaptured", "outboundBytes", "activeConnections", "suspiciousConnections"}
TRAFFIC_KEYS = {"time", "outbound", "inbound", "suspicious"}


def _seed():
    """Insert a couple of representative rows into the isolated DB."""
    conn = db.get_connection()
    try:
        db.clear_all(conn)
        db.insert_event(
            conn,
            timestamp="2026-10-05T14:06:41Z",
            source_ip="192.168.1.57",
            destination_ip="203.0.113.58",
            destination_host="files-transfer.example-share.net",
            protocol="HTTPS",
            port=443,
            packet_size_bytes=50_529_280,
            direction="OUTBOUND",
            risk="HIGH",
            usb_session=None,
        )
        db.insert_event(
            conn,
            timestamp="2026-10-05T14:01:47Z",
            source_ip="192.168.1.57",
            destination_ip="192.168.1.10",
            destination_host="fileserver.corp.local",
            protocol="SMB",
            port=445,
            packet_size_bytes=262_144,
            direction="INTERNAL",
            risk="LOW",
            usb_session="USB-S-0417",
        )
        db.insert_traffic_stat(
            conn,
            timestamp="2026-10-05T14:00:00Z",
            bytes_out=49_600_000,
            bytes_in=4_800_000,
            suspicious_bytes=48_200_000,
            packets=1200,
            active_connections=5,
        )
        db.insert_alert(
            conn,
            timestamp="2026-10-05T14:06:41Z",
            dst_ip="203.0.113.58",
            dst_port=443,
            reason="Volumetric outbound anomaly",
            severity="high",
            bytes=50_529_280,
            zscore=7.4,
            event_id=1,
        )
    finally:
        conn.close()


def test_events_shape(client):
    _seed()
    resp = client.get("/api/network/events")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list) and len(data) == 2

    first = data[0]
    assert set(first.keys()) == EVENT_KEYS
    assert first["id"] == "n-01"  # 'n-01' style
    assert isinstance(first["port"], int)
    assert isinstance(first["packetSizeBytes"], int)
    assert first["direction"] in {"OUTBOUND", "INBOUND", "INTERNAL"}
    assert first["risk"] in {"LOW", "MEDIUM", "HIGH"}
    assert first["protocol"] in {"HTTPS", "TCP", "DNS", "SMB"}
    assert first["usbSession"] is None  # null until correlation sets it
    assert data[1]["usbSession"] == "USB-S-0417"


def test_events_time_filter(client):
    _seed()
    only_first = client.get("/api/network/events?start=2026-10-05T14:05:00Z").get_json()
    assert len(only_first) == 1
    assert only_first[0]["id"] == "n-01"


def test_events_bad_range(client):
    _seed()
    resp = client.get("/api/network/events?start=2026-10-06T00:00:00Z&end=2026-10-05T00:00:00Z")
    assert resp.status_code == 400


def test_stats_shape(client):
    _seed()
    resp = client.get("/api/network/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert set(data.keys()) == STATS_KEYS
    assert data["packetsCaptured"] == 1200
    assert data["outboundBytes"] == 49_600_000
    assert data["suspiciousConnections"] == 1
    assert isinstance(data["activeConnections"], int)


def test_traffic_shape(client):
    _seed()
    resp = client.get("/api/network/traffic")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list) and len(data) == 1
    bucket = data[0]
    assert set(bucket.keys()) == TRAFFIC_KEYS
    assert bucket["time"] == "14:00"
    assert bucket["outbound"] == 49.6
    assert bucket["inbound"] == 4.8
    assert bucket["suspicious"] == 48.2


def test_empty_db_returns_shapes(client):
    resp = client.get("/api/network/events")
    assert resp.get_json() == []
    stats = client.get("/api/network/stats").get_json()
    assert set(stats.keys()) == STATS_KEYS
    assert stats["packetsCaptured"] == 0
    assert client.get("/api/network/traffic").get_json() == []
