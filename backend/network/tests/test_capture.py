"""End-to-end tests for flow aggregation, persistence and correlation helper."""

from __future__ import annotations

from backend.network import db
from backend.network.capture import CaptureEngine, direction_for
from backend.network.correlation import get_events_in_window, tag_usb_session
from backend.network.detector import Flow


def test_direction_for():
    assert direction_for("192.168.1.57", "203.0.113.58") == "OUTBOUND"
    assert direction_for("198.51.100.23", "192.168.1.57") == "INBOUND"
    assert direction_for("192.168.1.57", "192.168.1.10") == "INTERNAL"


def test_engine_flush_persists_and_detects(temp_db):
    engine = CaptureEngine(db_path=temp_db, mode="simulate", usb_session_id=None)
    engine.open()
    db.clear_all(engine._conn)

    # Build a baseline of quiet intervals.
    for i in range(20):
        engine.ingest_flow(Flow(src_ip="192.168.1.57", dst_ip="142.250.183.14", dst_port=443, protocol="HTTPS", bytes_out=20_000, hostname="www.google.com"))
        engine.flush_interval(f"2026-10-05T14:{i:02d}:00Z")

    # The burst.
    engine.ingest_flow(Flow(src_ip="192.168.1.57", dst_ip="203.0.113.58", dst_port=443, protocol="HTTPS", bytes_out=50_529_280, hostname="files-transfer.example-share.net"))
    engine.flush_interval("2026-10-05T14:30:00Z")
    engine.close_session()

    conn = db.get_connection(temp_db)
    try:
        events = db.fetch_events(conn)
        alerts = db.fetch_alerts(conn)

        burst = [e for e in events if e["destination_ip"] == "203.0.113.58"]
        assert burst, "the exfil flow should be recorded as a network_event"
        assert burst[0]["risk"] == "HIGH"
        assert burst[0]["direction"] == "OUTBOUND"
        assert burst[0]["protocol"] == "HTTPS"
        assert burst[0]["destination_host"] == "files-transfer.example-share.net"

        assert any(a["severity"] == "high" for a in alerts)

        summary = db.fetch_stats_summary(conn)
        assert summary["packetsCaptured"] > 0
        assert summary["outboundBytes"] > 0
    finally:
        conn.close()


def test_correlation_window_and_tagging(temp_db):
    engine = CaptureEngine(db_path=temp_db, mode="simulate", usb_session_id=None)
    engine.open()
    db.clear_all(engine._conn)
    engine.ingest_flow(Flow(src_ip="192.168.1.57", dst_ip="203.0.113.58", dst_port=443, protocol="HTTPS", bytes_out=1_000_000, hostname="files-transfer.example-share.net"))
    engine.flush_interval("2026-10-05T14:06:41Z")
    engine.close_session()

    window = get_events_in_window("2026-10-05T14:00:00Z", "2026-10-05T14:10:00Z", db_path=temp_db)
    assert set(window.keys()) == {"events", "flows", "alerts"}
    assert len(window["events"]) == 1
    assert window["events"][0]["usbSession"] is None

    # Correlation engine can now stamp the USB session.
    touched = tag_usb_session("2026-10-05T14:00:00Z", "2026-10-05T14:10:00Z", "USB-S-0417", db_path=temp_db)
    assert touched == 1
    window2 = get_events_in_window("2026-10-05T14:00:00Z", "2026-10-05T14:10:00Z", db_path=temp_db)
    assert window2["events"][0]["usbSession"] == "USB-S-0417"


def test_live_mode_without_pyshark_errors_clearly(temp_db, monkeypatch):
    # Pretend pyshark is unavailable.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("pyshark"):
            raise ImportError("no pyshark")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    engine = CaptureEngine(db_path=temp_db, mode="live")
    try:
        engine.start()
    except RuntimeError as exc:
        assert "pyshark" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("expected a clear RuntimeError")
