"""Live / simulated packet capture and flow aggregation.

Modes
-----
* ``live``   - PyShark + TShark on a real interface (needs TShark + privileges).
* ``simulate`` - synthetic but realistic traffic, no root/TShark required.
* ``pcap``   - replay a ``.pcap`` file through the same pipeline.

The engine aggregates packets into per-interval flows, writes connections /
traffic stats / events / alerts to SQLite, and is safe to start and stop from a
background thread so the correlation engine can bracket a USB session.

Public API::

    start_capture(session_label=None, usb_session_id=None, mode="simulate", ...)
    stop_capture()
    get_capture_status()
"""

from __future__ import annotations

import logging
import queue
import random
import shutil
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from . import config, db
from .detector import (
    FirstSeenTracker,
    Flow,
    IntervalStats,
    OutboundBaseline,
    classify_flow_risk,
    detect_interval,
    is_private,
    is_public,
)
from .timeutil import iso_now, to_iso_utc, utcnow

log = logging.getLogger("exfiltrace.network.capture")

# Ports -> friendly protocol names for the frontend contract.
_PORT_PROTOCOL = {53: "DNS", 443: "HTTPS", 445: "SMB", 80: "HTTP"}


@dataclass
class ParsedPacket:
    """Minimal packet view shared by all capture modes."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    length: int
    protocol: str = "TCP"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    hostname: Optional[str] = None


def _protocol_for(transport: str, dst_port: Optional[int], src_port: Optional[int]) -> str:
    """Best-effort protocol name from transport + ports."""
    for port in (dst_port, src_port):
        if port in _PORT_PROTOCOL:
            return _PORT_PROTOCOL[port]
    return transport


def direction_for(src_ip: str, dst_ip: str) -> str:
    """OUTBOUND | INBOUND | INTERNAL, based on which side is a private address."""
    src_priv, dst_priv = is_private(src_ip), is_private(dst_ip)
    if src_priv and dst_priv:
        return "INTERNAL"
    if src_priv and not dst_priv:
        return "OUTBOUND"
    if dst_priv and not src_priv:
        return "INBOUND"
    return "OUTBOUND"


def _merge_flow(flows: dict, packet: ParsedPacket, direction: str) -> None:
    """Fold a packet into the aggregated flow keyed by (src,dst,dport,proto)."""
    key = (packet.src_ip, packet.dst_ip, packet.dst_port, packet.protocol)
    flow = flows.get(key)
    ts = to_iso_utc(packet.timestamp)
    if flow is None:
        flow = Flow(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            src_port=packet.src_port,
            protocol=packet.protocol,
            first_seen=ts,
            last_seen=ts,
            hostname=packet.hostname,
        )
        flows[key] = flow
    if direction == "INBOUND":
        flow.bytes_in += packet.length
    else:
        flow.bytes_out += packet.length
    flow.packets += 1
    flow.last_seen = ts
    if packet.hostname and not flow.hostname:
        flow.hostname = packet.hostname


class SimulatedTrafficSource:
    """Deterministic-ish synthetic traffic so demos work without TShark/root."""

    def __init__(self, local_ip: str = config.SIM_LOCAL_IP, seed: Optional[int] = 1337) -> None:
        self.local_ip = local_ip
        self._rng = random.Random(seed)

    def generate(self, interval_index: int, now: datetime) -> list[ParsedPacket]:
        """Return the packets for one interval."""
        rng = self._rng
        local = self.local_ip
        packets: list[ParsedPacket] = []

        def add(src, dst, dport, proto, length, sport=None, host=None):
            packets.append(ParsedPacket(now, src, dst, length, proto, sport, dport, host))

        # Routine background traffic.
        add(local, "192.168.1.1", 53, "DNS", rng.randint(70, 120), rng.randint(30000, 60000))
        add(local, "192.168.1.10", 445, "SMB", rng.randint(120_000, 400_000), rng.randint(30000, 60000), "fileserver.corp.local")
        add(local, "142.250.183.14", 443, "HTTPS", rng.randint(10_000, 40_000), rng.randint(30000, 60000), "www.google.com")
        add(local, "13.107.42.14", 443, "HTTPS", rng.randint(30_000, 80_000), rng.randint(30000, 60000), "outlook.office365.com")
        add("104.18.32.47", local, 443, "HTTPS", rng.randint(20_000, 60_000), 443, "cdn.updates.vendor.com")

        # Occasional large upload to a personal cloud host (medium risk).
        if interval_index > 0 and interval_index % 20 == 0:
            add(local, "198.51.100.77", 443, "HTTPS", 8 * 1024 * 1024, rng.randint(30000, 60000), "dl.personal-cloud-drive.io")

        return packets


class CaptureEngine:
    """Owns the capture thread, flow table, detector state and DB writes."""

    def __init__(
        self,
        *,
        db_path: Optional[str] = None,
        interface: Optional[str] = None,
        mode: str = "simulate",
        pcap_file: Optional[str] = None,
        session_label: Optional[str] = None,
        usb_session_id: Optional[str] = None,
        interval_seconds: Optional[float] = None,
        local_ip: Optional[str] = None,
    ) -> None:
        self.db_path = db_path
        self.interface = interface or config.CAPTURE_INTERFACE
        self.mode = mode
        self.pcap_file = pcap_file
        self.session_label = session_label
        self.usb_session_id = usb_session_id
        self.interval_seconds = float(interval_seconds or config.STATS_INTERVAL_SECONDS)
        self.local_ip = local_ip or config.SIM_LOCAL_IP

        self.baseline = OutboundBaseline()
        self.tracker = FirstSeenTracker()
        self.dns_map: dict[str, str] = {}

        self._flows: dict = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._worker: Optional[threading.Thread] = None
        self._packet_queue: "queue.Queue[ParsedPacket]" = queue.Queue(maxsize=100_000)
        self._conn: Optional[object] = None
        self._session_id: Optional[int] = None

        self._status = {
            "running": False,
            "mode": mode,
            "interface": self.interface,
            "started_at": None,
            "last_flush": None,
            "packets": 0,
            "flows": 0,
            "events": 0,
            "alerts": 0,
            "session_label": session_label,
            "usb_session_id": usb_session_id,
            "last_error": None,
        }

    # -- lifecycle -----------------------------------------------------------
    def open(self) -> "CaptureEngine":
        """Open the DB connection and a capture-session row without starting a thread."""
        if self._conn is None:
            self._conn = db.get_connection(self.db_path)
            db.init_db(self._conn)
        if self._session_id is None:
            self._session_id = db.insert_capture_session(
                self._conn,
                started_at=iso_now(),
                trigger=self.session_label or self.mode,
                usb_session_id=self.usb_session_id,
            )
        return self

    def close_session(self) -> None:
        """Stamp the capture session's ``ended_at`` (safe to call twice)."""
        if self._conn is not None and self._session_id is not None:
            db.close_capture_session(self._conn, self._session_id, iso_now())
            self._session_id = None

    def start(self) -> dict:
        """Validate prerequisites, open a capture session and start the thread."""
        if self._status["running"]:
            return self.status()
        self._validate_mode()
        self.open()
        self._stop.clear()
        self._status.update(running=True, started_at=iso_now(), last_error=None)
        self._thread = threading.Thread(target=self._run_loop, name="exfiltrace-capture", daemon=True)
        self._thread.start()
        log.info("capture started (mode=%s, interface=%s)", self.mode, self.interface)
        return self.status()

    def stop(self, timeout: float = 5.0) -> dict:
        """Signal the thread to stop, flush remaining flows and close the session."""
        if not self._status["running"]:
            return self.status()
        self._stop.set()
        for thread in (self._thread, self._worker):
            if thread and thread.is_alive():
                thread.join(timeout=timeout)
        try:
            self.flush_interval()
        except Exception as exc:  # pragma: no cover - defensive
            self._status["last_error"] = str(exc)
            log.exception("error flushing on stop")
        self.close_session()
        self._status["running"] = False
        log.info("capture stopped")
        return self.status()

    def status(self) -> dict:
        """Snapshot of engine state for /status style introspection."""
        with self._lock:
            snapshot = dict(self._status)
            snapshot["flows"] = len(self._flows)
        return snapshot

    # -- validation ----------------------------------------------------------
    def _validate_mode(self) -> None:
        if self.mode == "live":
            try:
                import pyshark  # noqa: F401
            except Exception as exc:  # pragma: no cover - env dependent
                raise RuntimeError(
                    "Live capture needs the 'pyshark' package. Install it with "
                    "'pip install pyshark' and make sure TShark is on PATH."
                ) from exc
            if shutil.which("tshark") is None:
                raise RuntimeError(
                    "TShark was not found on PATH. Install Wireshark/TShark, then retry. "
                    "Live capture also needs packet-capture privileges (sudo / Npcap)."
                )
        elif self.mode == "pcap":
            if not self.pcap_file:
                raise RuntimeError("PCAP replay requires a pcap_file path.")
        elif self.mode != "simulate":
            raise RuntimeError(f"Unknown capture mode: {self.mode!r}")

    # -- ingestion -----------------------------------------------------------
    def ingest_packet(self, packet: ParsedPacket) -> None:
        """Add one packet to the current flow table (thread-safe)."""
        direction = direction_for(packet.src_ip, packet.dst_ip)
        with self._lock:
            _merge_flow(self._flows, packet, direction)
            if packet.hostname and is_public(packet.dst_ip):
                self.dns_map[packet.dst_ip] = packet.hostname

    def ingest_flow(self, flow: Flow) -> None:
        """Directly merge an already-aggregated flow (used by tests/demos)."""
        if not flow.packets and (flow.bytes_out + flow.bytes_in) > 0:
            # Callers that inject pre-aggregated bytes may omit the packet count.
            flow.packets = max(1, int((flow.bytes_out + flow.bytes_in) // 1400))
        # NB: leave first_seen/last_seen as-is when unset; flush_interval stamps
        # them with the interval timestamp so injected flows land in the right bucket.
        with self._lock:
            key = (flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)
            existing = self._flows.get(key)
            if existing is None:
                self._flows[key] = flow
            else:
                existing.bytes_out += flow.bytes_out
                existing.bytes_in += flow.bytes_in
                existing.packets += flow.packets
                existing.last_seen = flow.last_seen or existing.last_seen
                existing.first_seen = existing.first_seen or flow.first_seen
                if flow.hostname and not existing.hostname:
                    existing.hostname = flow.hostname

    def flush_interval(self, timestamp: Optional[str] = None) -> dict:
        """Aggregate current flows, persist everything, run detection.

        Returns a small summary (interval, events, alerts) and resets the flow table.
        """
        assert self._conn is not None, "engine not started"
        ts = timestamp or iso_now()
        with self._lock:
            flows = list(self._flows.values())
            self._flows = {}

        if not flows:
            # Keep the baseline ticking even across quiet intervals.
            stats = IntervalStats(timestamp=ts, bytes_out=0, bytes_in=0, packets=0, active_connections=0)
            alerts = detect_interval(stats, [], self.baseline, self.tracker)
            db.insert_traffic_stat(
                self._conn,
                timestamp=ts,
                bytes_out=0,
                bytes_in=0,
                suspicious_bytes=0,
                packets=0,
                active_connections=0,
            )
            self._status["last_flush"] = ts
            return {"interval": ts, "events": 0, "alerts": len(alerts)}

        bytes_out = sum(f.bytes_out for f in flows)
        bytes_in = sum(f.bytes_in for f in flows)
        packets = sum(f.packets for f in flows)
        stats = IntervalStats(
            timestamp=ts,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            packets=packets,
            active_connections=len(flows),
        )

        alerts = detect_interval(stats, flows, self.baseline, self.tracker)

        high_dsts = {a.dst_ip for a in alerts if a.severity == "high" and a.dst_ip}
        flagged_dsts = {a.dst_ip for a in alerts if a.severity in ("medium", "high") and a.dst_ip}
        suspicious_bytes = sum(f.bytes_out for f in flows if f.dst_ip in flagged_dsts)

        # Persist raw flows.
        for f in flows:
            db.insert_connection(
                self._conn,
                src_ip=f.src_ip,
                src_port=f.src_port,
                dst_ip=f.dst_ip,
                dst_port=f.dst_port,
                protocol=f.protocol,
                bytes_out=f.bytes_out,
                bytes_in=f.bytes_in,
                packets=f.packets,
                first_seen=f.first_seen or ts,
                last_seen=f.last_seen or ts,
            )

        # Persist interval aggregate.
        db.insert_traffic_stat(
            self._conn,
            timestamp=ts,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            suspicious_bytes=suspicious_bytes,
            packets=packets,
            active_connections=len(flows),
        )

        # Persist notable flows as network_events.
        events_written = 0
        for f in flows:
            if f.bytes_out + f.bytes_in < config.MIN_EVENT_BYTES:
                continue
            direction = direction_for(f.src_ip, f.dst_ip)
            host = f.hostname or self.dns_map.get(f.dst_ip) or f.dst_ip
            db.insert_event(
                self._conn,
                timestamp=f.last_seen or ts,
                source_ip=f.src_ip,
                destination_ip=f.dst_ip,
                destination_host=host,
                protocol=f.protocol,
                port=f.dst_port,
                packet_size_bytes=f.bytes_out + f.bytes_in,
                direction=direction,
                risk=classify_flow_risk(f, high_dsts),
                usb_session=self.usb_session_id,
            )
            events_written += 1

        # Persist alerts.
        for a in alerts:
            db.insert_alert(
                self._conn,
                timestamp=a.timestamp,
                dst_ip=a.dst_ip,
                dst_port=a.dst_port,
                reason=a.reason,
                severity=a.severity,
                bytes=a.bytes,
                zscore=a.zscore,
            )

        with self._lock:
            self._status["last_flush"] = ts
            self._status["events"] += events_written
            self._status["alerts"] += len(alerts)

        return {"interval": ts, "events": events_written, "alerts": len(alerts)}

    # -- run loops -----------------------------------------------------------
    def _run_loop(self) -> None:
        try:
            if self.mode == "live":
                self._run_live()
            elif self.mode == "pcap":
                self._run_pcap()
            else:
                self._run_simulation()
        except Exception as exc:  # pragma: no cover - env dependent
            log.exception("capture loop crashed")
            self._status["last_error"] = str(exc)
            self._status["running"] = False

    def _run_simulation(self) -> None:
        source = SimulatedTrafficSource(local_ip=self.local_ip)
        index = 0
        next_flush = utcnow()
        while not self._stop.is_set():
            now = utcnow()
            for packet in source.generate(index, now):
                self.ingest_packet(packet)
                self._status["packets"] += 1
            index += 1
            now = utcnow()
            if now >= next_flush:
                self.flush_interval(to_iso_utc(now))
                next_flush = datetime.fromtimestamp(now.timestamp() + self.interval_seconds, tz=timezone.utc)
            self._stop.wait(config.SIM_INTERVAL_SECONDS)

    def _run_live(self) -> None:
        import pyshark  # imported lazily; validated in _validate_mode

        capture = pyshark.LiveCapture(interface=self.interface, use_json=True, include_raw=False)

        def worker() -> None:
            try:
                for packet in capture.sniff_continuously():
                    if self._stop.is_set():
                        break
                    parsed = self._parse_pyshark_packet(packet)
                    if parsed is not None:
                        try:
                            self._packet_queue.put(parsed, timeout=1)
                        except queue.Full:  # pragma: no cover
                            log.warning("packet queue full; dropping packet")
            except Exception as exc:  # pragma: no cover - env dependent
                self._status["last_error"] = f"live capture stopped: {exc}"
                log.exception("live capture worker error")

        self._worker = threading.Thread(target=worker, name="exfiltrace-pyshark", daemon=True)
        self._worker.start()

        next_flush = utcnow().timestamp() + self.interval_seconds
        while not self._stop.is_set():
            drained = False
            try:
                while True:
                    packet = self._packet_queue.get_nowait()
                    self.ingest_packet(packet)
                    self._status["packets"] += 1
                    drained = True
            except queue.Empty:
                pass
            if utcnow().timestamp() >= next_flush:
                self.flush_interval()
                next_flush = utcnow().timestamp() + self.interval_seconds
            self._stop.wait(0.2 if drained else 0.5)

    def _run_pcap(self) -> None:
        import pyshark

        capture = pyshark.FileCapture(self.pcap_file, keep_packets=False)
        window_start: Optional[float] = None
        for packet in capture:
            if self._stop.is_set():
                break
            parsed = self._parse_pyshark_packet(packet)
            if parsed is None:
                continue
            ts = parsed.timestamp.timestamp()
            if window_start is None:
                window_start = ts
            if ts - window_start >= self.interval_seconds:
                self.flush_interval(to_iso_utc(parsed.timestamp))
                window_start = ts
            self.ingest_packet(parsed)
            self._status["packets"] += 1
        capture.close()
        self.flush_interval()

    @staticmethod
    def _parse_pyshark_packet(packet) -> Optional[ParsedPacket]:
        """Convert a PyShark packet into a ParsedPacket (best effort)."""
        try:
            ts = float(packet.sniff_timestamp)
            when = datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            when = utcnow()

        src_ip = dst_ip = None
        for layer in ("ip", "ipv6"):
            if hasattr(packet, layer):
                lyr = getattr(packet, layer)
                src_ip = getattr(lyr, "src", None)
                dst_ip = getattr(lyr, "dst", None)
                if src_ip and dst_ip:
                    break
        if not src_ip or not dst_ip:
            return None

        transport = "TCP"
        src_port = dst_port = None
        if hasattr(packet, "tcp"):
            transport, src_port, dst_port = "TCP", _int(getattr(packet.tcp, "srcport", None)), _int(getattr(packet.tcp, "dstport", None))
        elif hasattr(packet, "udp"):
            transport, src_port, dst_port = "UDP", _int(getattr(packet.udp, "srcport", None)), _int(getattr(packet.udp, "dstport", None))

        hostname = None
        if hasattr(packet, "dns"):
            hostname = getattr(packet.dns, "qry_name", None)
        elif hasattr(packet, "tls"):
            hostname = getattr(packet.tls, "handshake_extensions_server_name", None)

        protocol = _protocol_for(transport, dst_port, src_port)
        length = _int(getattr(packet, "length", None)) or 0
        return ParsedPacket(when, src_ip, dst_ip, length, protocol, src_port, dst_port, hostname)


def _int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# Module-level singleton + public functions
# --------------------------------------------------------------------------
_engine: Optional[CaptureEngine] = None
_engine_lock = threading.Lock()


def start_capture(
    session_label: Optional[str] = None,
    usb_session_id: Optional[str] = None,
    *,
    mode: str = "simulate",
    interface: Optional[str] = None,
    pcap_file: Optional[str] = None,
    db_path: Optional[str] = None,
    interval_seconds: Optional[float] = None,
) -> dict:
    """Start (or return the running) capture engine.

    ``usb_session_id`` lets the correlation engine tag every event produced while
    the session is active.
    """
    global _engine
    with _engine_lock:
        if _engine is not None and _engine.status()["running"]:
            return _engine.status()
        _engine = CaptureEngine(
            db_path=db_path,
            interface=interface,
            mode=mode,
            pcap_file=pcap_file,
            session_label=session_label,
            usb_session_id=usb_session_id,
            interval_seconds=interval_seconds,
        )
        return _engine.start()


def stop_capture() -> dict:
    """Stop the running capture engine (no-op if none is running)."""
    global _engine
    with _engine_lock:
        if _engine is None:
            return {"running": False}
        return _engine.stop()


def get_capture_status() -> dict:
    """Return the capture engine status (or an idle placeholder)."""
    with _engine_lock:
        if _engine is None:
            return {"running": False, "mode": None, "interface": None}
        return _engine.status()


def get_engine() -> Optional[CaptureEngine]:
    """Return the active engine instance (used by tests/demos)."""
    return _engine
