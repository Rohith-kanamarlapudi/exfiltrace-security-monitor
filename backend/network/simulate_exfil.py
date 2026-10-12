"""Demo: reproduce the mock exfiltration scenario without touching the network.

It builds ~25 quiet intervals to establish a baseline, then sends a ~48 MB
OUTBOUND HTTPS burst to 203.0.113.58 (files-transfer.example-share.net) inside a
USB-session-length window, so the volumetric + first-seen rules fire a HIGH-risk
alert.  All traffic is *injected* - nothing leaves the machine.

Run from the repository root::

    python -m backend.network.simulate_exfil            # clean demo DB
    python -m backend.network.simulate_exfil --append   # keep existing rows
    python -m backend.network.simulate_exfil --db /tmp/demo.db
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timezone

from . import config, db
from .capture import CaptureEngine
from .detector import Flow
from .timeutil import parse_iso, to_iso_utc

# Scenario constants (mirrors src/data/mockData.js).
EXFIL_IP = "203.0.113.58"
EXFIL_HOST = "files-transfer.example-share.net"
EXFIL_BYTES = 50_529_280  # ~48.2 MB, matches mock event n-01
LOCAL_IP = config.SIM_LOCAL_IP
START = "2026-10-05T13:40:00Z"
INTERVAL_SECONDS = 60
BASELINE_INTERVALS = 25


def _flow(dst_ip, dst_port, protocol, out_bytes, host=None, in_bytes=0) -> Flow:
    return Flow(
        src_ip=LOCAL_IP,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        bytes_out=out_bytes,
        bytes_in=in_bytes,
        packets=max(1, out_bytes // 1400),
        hostname=host,
    )


_RNG = random.Random(20261005)


def _background_flows() -> list[Flow]:
    """One interval of ordinary office traffic (with realistic jitter)."""
    return [
        _flow("192.168.1.1", 53, "DNS", _RNG.randint(70, 120)),
        _flow("192.168.1.10", 445, "SMB", _RNG.randint(180_000, 320_000), host="fileserver.corp.local"),
        _flow("142.250.183.14", 443, "HTTPS", _RNG.randint(12_000, 25_000), host="www.google.com"),
        _flow("13.107.42.14", 443, "HTTPS", _RNG.randint(30_000, 55_000), host="outlook.office365.com"),
        _flow("198.51.100.23", 3389, "TCP", 0, in_bytes=_RNG.randint(600, 900), host="wkstn-fin-07.corp.local"),
    ]


def run_demo(db_path: str | None = None, clean: bool = True) -> dict:
    """Run the scripted scenario and return a small report."""
    engine = CaptureEngine(db_path=db_path, mode="simulate", session_label="simulate-exfil", usb_session_id="USB-S-0417")
    engine.open()

    if clean:
        db.clear_all(engine._conn)  # noqa: SLF001 - demo convenience

    start_dt = parse_iso(START)

    # Phase 1: quiet baseline so the volumetric rule has enough samples.
    for i in range(BASELINE_INTERVALS):
        ts = to_iso_utc(datetime.fromtimestamp(start_dt.timestamp() + i * INTERVAL_SECONDS, tz=timezone.utc))
        for flow in _background_flows():
            engine.ingest_flow(flow)
        engine.flush_interval(ts)

    # Phase 2: DNS lookup then the big upload in a single interval.
    burst_ts = to_iso_utc(datetime.fromtimestamp(start_dt.timestamp() + BASELINE_INTERVALS * INTERVAL_SECONDS, tz=timezone.utc))
    engine.ingest_flow(_flow(EXFIL_IP, 53, "DNS", 96))
    engine.ingest_flow(_flow(EXFIL_IP, 443, "HTTPS", EXFIL_BYTES, host=EXFIL_HOST))
    summary = engine.flush_interval(burst_ts)

    # Phase 3: a couple of quiet intervals so the burst doesn't leak into the baseline.
    for i in range(1, 3):
        ts = to_iso_utc(datetime.fromtimestamp(start_dt.timestamp() + (BASELINE_INTERVALS + i) * INTERVAL_SECONDS, tz=timezone.utc))
        for flow in _background_flows():
            engine.ingest_flow(flow)
        engine.flush_interval(ts)

    engine.close_session()

    alerts = db.fetch_alerts(engine._conn, start=START)
    events = db.fetch_events(engine._conn, start=START)
    return {"summary": summary, "alerts": alerts, "events": events, "db_path": db_path or config.get_db_path()}


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Simulate the ExfilTrace exfiltration scenario (no real traffic).")
    parser.add_argument("--db", default=None, help="SQLite path (default: module DB)")
    parser.add_argument("--append", action="store_true", help="Do not clear existing rows first")
    args = parser.parse_args()

    result = run_demo(db_path=args.db, clean=not args.append)

    print(f"\nDemo complete. Database: {result['db_path']}")
    print(f"Intervals flushed on burst: {result['summary']}")

    print(f"\nEvents written: {len(result['events'])}")
    for row in result["events"]:
        print(f"  n-{row['id']:02d}  {row['timestamp']}  {row['direction']:<8} {row['protocol']:<5} "
              f"{row['destination_ip']}:{row['port']}  risk={row['risk']}  {row['packet_size_bytes']} bytes")

    print(f"\nAlerts fired: {len(result['alerts'])}")
    for row in result["alerts"]:
        print(f"  [{row['severity'].upper():<6}] {row['timestamp']}  -> {row['dst_ip']}:{row['dst_port']}  "
              f"z={row['zscore']}  {row['reason']}")

    print("\nNow run the API and curl the endpoints:")
    print("  python -m backend.network.app")
    print("  curl -s localhost:5000/api/network/events | python -m json.tool")


if __name__ == "__main__":
    main()
