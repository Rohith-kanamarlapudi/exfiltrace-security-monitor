"""Live-capture helpers tested without opening a real capture device.

These tests mock PyShark packets and the LiveCapture object, so they exercise
the metadata-only pipeline without requiring ChmodBPF, TShark permissions, or
an active network interface.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from backend.network import capture, config, db
from backend.network.capture import (
    CaptureEngine,
    ParsedPacket,
    direction_for,
    is_loopback_ip,
    is_self_traffic,
    list_capture_interfaces,
    validate_capture_interface,
)
from backend.network.combined import LiveConfigError, resolve_live_db


def _packet(src="192.168.0.119", dst="93.184.216.34", sport=51000, dport=443, host=None, length=1500):
    return ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_ip=src,
        dst_ip=dst,
        length=length,
        protocol="HTTPS",
        src_port=sport,
        dst_port=dport,
        hostname=host,
    )


def _pyshark_packet(src="192.168.0.119", dst="93.184.216.34", host="example.org"):
    return SimpleNamespace(
        sniff_timestamp="1780000000.0",
        ip=SimpleNamespace(src=src, dst=dst),
        tcp=SimpleNamespace(srcport="51000", dstport="443"),
        tls=SimpleNamespace(handshake_extensions_server_name=host),
        length="1500",
    )


class _TsharkResult:
    returncode = 0
    stdout = "1. ap1\n2. en0 (Wi-Fi)\n13. lo0 (Loopback)\n"
    stderr = ""


def test_interface_listing_and_validation(monkeypatch):
    monkeypatch.setattr(capture.platform_support, "find_tshark", lambda _explicit=None, **_kwargs: "/usr/bin/tshark")
    monkeypatch.setattr(
        capture.platform_support.subprocess, "run", lambda *_args, **_kwargs: _TsharkResult()
    )

    assert list_capture_interfaces() == ["ap1", "en0", "lo0"]
    assert validate_capture_interface("en0") == "en0"
    with pytest.raises(RuntimeError, match="not available"):
        validate_capture_interface("en9")


def test_direction_uses_local_interface_ip():
    local = "192.168.0.119"
    assert direction_for(local, "203.0.113.58", local) == "OUTBOUND"
    assert direction_for("203.0.113.58", local, local) == "INBOUND"
    assert direction_for("192.168.0.10", "192.168.0.20", local) == "INTERNAL"


def test_loopback_and_backend_traffic_are_excluded():
    assert is_loopback_ip("127.0.0.1")
    assert is_loopback_ip("::1")
    assert is_self_traffic(_packet(src="127.0.0.1", dst="127.0.0.1"))
    local = "192.168.0.119"
    assert is_self_traffic(_packet(dst=local, dport=5001), local)
    assert is_self_traffic(_packet(dst=local, dport=5173), local)
    assert is_self_traffic(_packet(src="93.184.216.34", dst=local, sport=443, dport=5001), local)
    assert is_self_traffic(_packet(src="93.184.216.34", dst=local, sport=443, dport=5173), local)
    assert is_self_traffic(_packet(src=local, dst="93.184.216.34", sport=5001, dport=443), local)
    assert not is_self_traffic(_packet(dst="93.184.216.34", dport=443), local)


def test_pyshark_packet_is_metadata_only():
    parsed = CaptureEngine._parse_pyshark_packet(_pyshark_packet())
    assert parsed is not None
    assert parsed.src_ip == "192.168.0.119"
    assert parsed.dst_ip == "93.184.216.34"
    assert parsed.dst_port == 443
    assert parsed.protocol == "HTTPS"
    assert parsed.hostname == "example.org"
    assert parsed.length == 1500
    assert not hasattr(parsed, "payload")
    assert not hasattr(parsed, "raw")


def test_live_flow_stats_and_alerts_use_metadata(temp_db):
    engine = CaptureEngine(
        db_path=temp_db,
        mode="simulate",
        local_ip="192.168.0.119",
    )
    engine.open()
    db.clear_all(engine._conn)

    # Establish a quiet baseline, then inject one large outbound flow.
    for i in range(20):
        engine.ingest_packet(_packet(dst="142.250.183.14", dport=443, length=20_000))
        engine.flush_interval(f"2026-10-05T14:{i:02d}:00Z")

    engine.ingest_packet(
        _packet(dst="203.0.113.58", dport=443, host="files-transfer.example-share.net", length=50_000_000)
    )
    result = engine.flush_interval("2026-10-05T14:30:00Z")
    assert result["events"] == 1
    assert result["alerts"] >= 1
    engine.close_session()

    conn = db.get_connection(temp_db)
    try:
        event = db.fetch_events(conn)[0]
        assert event["direction"] == "OUTBOUND"
        assert event["risk"] == "HIGH"
        assert event["destination_host"] == "files-transfer.example-share.net"
        assert event["usb_session"] is None
        assert db.fetch_traffic_stats(conn)[-1]["bytes_out"] >= 50_000_000
        assert db.fetch_stats_summary(conn)["packetsCaptured"] == 21
        assert db.fetch_alerts(conn)
    finally:
        conn.close()

    # The schema contains counters and metadata only; no payload columns exist.
    conn = db.get_connection(temp_db)
    try:
        for table in ("network_events", "connections", "traffic_stats", "alerts"):
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
            assert not columns & {"payload", "raw_packet", "packet_data", "raw"}
    finally:
        conn.close()


def test_live_engine_shutdown_closes_capture(monkeypatch, temp_db):
    class FakeLiveCapture:
        instances = []

        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.closed = False
            FakeLiveCapture.instances.append(self)

        def sniff_continuously(self):
            while True:
                yield _pyshark_packet()
                time.sleep(0.01)

        def close(self):
            self.closed = True

    monkeypatch.setattr(capture.platform_support, "find_tshark", lambda _explicit=None, **_kwargs: "/usr/bin/tshark")
    monkeypatch.setattr(
        capture, "resolve_capture_interface", lambda interface, tshark_path=None: interface
    )
    monkeypatch.setitem(sys.modules, "pyshark", SimpleNamespace(LiveCapture=FakeLiveCapture))

    engine = CaptureEngine(
        db_path=temp_db,
        mode="live",
        interface="en0",
        local_ip="192.168.0.119",
        interval_seconds=0.05,
    )
    engine.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not FakeLiveCapture.instances:
        time.sleep(0.01)

    assert FakeLiveCapture.instances
    fake_capture = FakeLiveCapture.instances[0]
    assert fake_capture.kwargs["custom_parameters"] == ["-p"]
    time.sleep(0.15)
    status = engine.stop()

    assert status["running"] is False
    assert fake_capture.closed is True
    assert engine._thread is not None and not engine._thread.is_alive()


def test_live_db_refuses_demo_database(tmp_path, monkeypatch):
    demo = tmp_path / "exfil_demo.db"
    monkeypatch.setattr(config, "default_demo_db", lambda: demo)
    with pytest.raises(LiveConfigError, match="demo database"):
        resolve_live_db(str(demo))
    expected = os.path.realpath(str(tmp_path / "live.db"))
    assert resolve_live_db(str(tmp_path / "live.db")) == expected


def test_live_capture_startup_failure_is_isolated(monkeypatch, tmp_path):
    from backend.network import combined

    args = SimpleNamespace(interface="en9", promiscuous=False, capture_seconds=None, tshark_path=None)
    started = {"called": False}

    def reject(_interface, _tshark_path=None):
        raise RuntimeError("interface is not available")

    monkeypatch.setattr(capture.platform_support, "find_tshark", lambda _explicit=None, **_kwargs: "/usr/bin/tshark")
    monkeypatch.setattr(capture, "validate_capture_interface", reject)
    monkeypatch.setattr(capture, "start_capture", lambda **_kwargs: started.update(called=True))

    assert combined.start_live_capture(args, str(tmp_path / "live.db"), 5001) is None
    assert started["called"] is False


def test_pyshark_dotted_json_metadata_fields_are_read():
    class DottedLayer:
        def __init__(self, field_name, value):
            self._field_name = field_name
            self._value = value

        def get_field(self, name):
            if name != self._field_name:
                raise AttributeError(name)
            return self._value

    base = dict(
        sniff_timestamp="1780000000.0",
        ip=SimpleNamespace(src="192.168.0.119", dst="93.184.216.34"),
        tcp=SimpleNamespace(srcport="51000", dstport="443"),
        length="1500",
    )

    dns_packet = SimpleNamespace(**base, dns=DottedLayer("qry.name", "dns.example.org"))
    tls_packet = SimpleNamespace(
        **base,
        tls=DottedLayer("handshake.extensions_server_name", "tls.example.org"),
    )

    assert CaptureEngine._parse_pyshark_packet(dns_packet).hostname == "dns.example.org"
    assert CaptureEngine._parse_pyshark_packet(tls_packet).hostname == "tls.example.org"


def test_dns_answers_map_later_flows_to_hostname(temp_db):
    class DnsLayer:
        def __init__(self):
            self._fields = {
                "qry.name": "www.example.org",
                "a": SimpleNamespace(
                    all_fields=[SimpleNamespace(raw_value="93.184.216.34"), SimpleNamespace(raw_value="203.0.113.10")]
                ),
            }

        def get_field(self, name):
            if name not in self._fields:
                raise AttributeError(name)
            return self._fields[name]

    packet = SimpleNamespace(
        sniff_timestamp="1780000000.0",
        ip=SimpleNamespace(src="192.168.0.119", dst="8.8.8.8"),
        udp=SimpleNamespace(srcport="51000", dstport="53"),
        length="100",
        dns=DnsLayer(),
    )
    parsed = CaptureEngine._parse_pyshark_packet(packet)
    assert parsed.hostname == "www.example.org"
    assert parsed.dns_answer_ips == ("93.184.216.34", "203.0.113.10")

    engine = CaptureEngine(db_path=temp_db, mode="simulate", local_ip="192.168.0.119")
    engine.open()
    db.clear_all(engine._conn)
    engine.ingest_packet(parsed)

    # The DNS server itself must not inherit the queried hostname.
    assert "8.8.8.8" not in engine.dns_map
    assert engine.dns_map["93.184.216.34"] == "www.example.org"
    engine.ingest_packet(_packet(dst="93.184.216.34", dport=443, length=1500))
    engine.flush_interval("2026-10-05T14:30:00Z")
    engine.close_session()

    conn = db.get_connection(temp_db)
    try:
        events = db.fetch_events(conn)
        assert any(event["destination_host"] == "www.example.org" for event in events)
        assert all("payload" not in dict(event) for event in events)
    finally:
        conn.close()


def test_pyshark_nested_dns_json_fields_are_read():
    """TShark nests DNS records under Queries/Answers in its JSON output."""

    class NestedDnsLayer:
        _all_fields = {
            "dns.count.queries": "1",
            "dns.count.answers": "1",
            "Queries": {
                "dns.Queries.www.example.org": {
                    "dns.qry.name": "www.example.org",
                    "dns.qry.type": "1",
                }
            },
            "Answers": {
                "dns.Answers.www.example.org": {
                    "dns.resp.name": "www.example.org",
                    "dns.a": "93.184.216.34",
                }
            },
        }

    packet = SimpleNamespace(
        sniff_timestamp="1780000000.0",
        ip=SimpleNamespace(src="192.168.0.119", dst="8.8.8.8"),
        udp=SimpleNamespace(srcport="51000", dstport="53"),
        length="100",
        dns=NestedDnsLayer(),
    )
    parsed = CaptureEngine._parse_pyshark_packet(packet)
    assert parsed.hostname == "www.example.org"
    assert parsed.dns_answer_ips == ("93.184.216.34",)


def test_pyshark_nested_tls_client_hello_sni_is_read():
    """TShark nests ClientHello metadata under the TLS record layer."""

    class NestedTlsLayer:
        _all_fields = {
            "tls.stream": "0",
            "tls.record": {
                "tls.record.content_type": "22",
                "tls.handshake": {
                    "tls.handshake.type": "1",
                    "tls.handshake.extension": {
                        "tls.handshake.extension.type": "0",
                        "Server Name Indication extension": {
                            "tls.handshake.extensions_server_name": "example.org"
                        },
                    },
                },
            },
        }

    packet = SimpleNamespace(
        sniff_timestamp="1780000000.0",
        ip=SimpleNamespace(src="192.168.0.119", dst="93.184.216.34"),
        tcp=SimpleNamespace(srcport="51000", dstport="443"),
        length="126",
        tls=NestedTlsLayer(),
    )
    parsed = CaptureEngine._parse_pyshark_packet(packet)
    assert parsed.hostname == "example.org"
