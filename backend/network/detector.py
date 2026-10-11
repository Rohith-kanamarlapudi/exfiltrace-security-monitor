"""Anomaly detection rules for outbound traffic.

Four readable rules (easy to justify in the lab report):

1. **Volumetric** - a rolling baseline of outbound bytes per interval; flag
   intervals above ``mean + k*std`` once enough samples exist, and above an
   absolute byte floor so tiny numbers never trip the rule.
2. **First-seen external destination** - a public IP we have never seen before
   receiving a significant amount of outbound data.
3. **Suspicious ports** - a configurable watchlist (FTP, Telnet, SMB, RDP, ...).
4. **Private ranges ignored** - RFC1918 / loopback / link-local destinations are
   never treated as "external" for rules 2-3.

Severity is derived from the z-score and byte volume; ``severity_to_risk`` maps
``low/medium/high`` -> ``LOW/MEDIUM/HIGH`` for the frontend.
"""

from __future__ import annotations

import ipaddress
import statistics
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from . import config
from .timeutil import to_iso_utc, utcnow


def is_private(ip: Optional[str]) -> bool:
    """True for RFC1918 / loopback / link-local / unique-local addresses."""
    if not ip:
        return False
    # Strip an IPv6 zone id if present (e.g. fe80::1%en0).
    ip = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Deliberately use the explicit local ranges rather than ``addr.is_private``:
    # Python also marks documentation ranges (e.g. 203.0.113.0/24) as private,
    # but those are used as *external* hosts throughout the mock scenario.
    return any(addr in net for net in config.PRIVATE_NETWORKS)


def is_public(ip: Optional[str]) -> bool:
    """Inverse of :func:`is_private` for a valid address."""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return not is_private(ip)


def is_suspicious_port(port: Optional[int]) -> bool:
    """True if the destination port is on the watchlist."""
    return port is not None and int(port) in set(config.SUSPICIOUS_PORTS)


@dataclass
class Flow:
    """A single aggregated conversation feeding the detector."""

    src_ip: str
    dst_ip: str
    dst_port: Optional[int]
    protocol: str
    bytes_out: int = 0
    bytes_in: int = 0
    packets: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    src_port: Optional[int] = None
    hostname: Optional[str] = None


@dataclass
class IntervalStats:
    """One aggregation interval of traffic."""

    timestamp: str
    bytes_out: int = 0
    bytes_in: int = 0
    packets: int = 0
    active_connections: int = 0


@dataclass
class Alert:
    """A detector finding, ready to persist and serialise."""

    timestamp: str
    reason: str
    severity: str  # low | medium | high
    bytes: int = 0
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    zscore: Optional[float] = None

    @property
    def risk(self) -> str:
        """Frontend-cased risk (LOW/MEDIUM/HIGH)."""
        return severity_to_risk(self.severity)


def severity_to_risk(severity: str) -> str:
    """low/medium/high -> LOW/MEDIUM/HIGH."""
    return {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}.get(str(severity).lower(), "LOW")


def severity_from(zscore: Optional[float], byte_count: int) -> str:
    """Derive severity from the z-score and absolute bytes (explainable rule)."""
    if (zscore is not None and zscore >= config.SEVERITY_HIGH_Z) or byte_count >= config.SEVERITY_HIGH_BYTES:
        return "high"
    if (zscore is not None and zscore >= config.SEVERITY_MEDIUM_Z) or byte_count >= config.SEVERITY_MEDIUM_BYTES:
        return "medium"
    return "low"


class OutboundBaseline:
    """Rolling baseline of outbound bytes-per-interval."""

    def __init__(
        self,
        k: float = config.ANOMALY_K,
        min_samples: int = config.MIN_BASELINE_SAMPLES,
        window: int = config.BASELINE_WINDOW,
        min_bytes: int = config.MIN_ABSOLUTE_BYTES,
    ) -> None:
        self.k = k
        self.min_samples = min_samples
        self.window = window
        self.min_bytes = min_bytes
        self._samples: list[float] = []

    def __len__(self) -> int:
        return len(self._samples)

    @property
    def samples(self) -> Sequence[float]:
        return tuple(self._samples)

    def mean(self) -> float:
        return statistics.fmean(self._samples) if self._samples else 0.0

    def std(self) -> float:
        # Population std is fine for a bounded rolling window.
        return statistics.pstdev(self._samples) if len(self._samples) > 1 else 0.0

    def zscore(self, value: float) -> float:
        """z-score of ``value`` against the current baseline (0 if no spread)."""
        std = self.std()
        if std <= 0:
            return 0.0
        return (value - self.mean()) / std

    def is_ready(self) -> bool:
        """True once enough samples have been collected to trust the rule."""
        return len(self._samples) >= self.min_samples

    def is_anomalous(self, value: float) -> tuple[bool, float]:
        """Return ``(is_anomaly, zscore)`` for a candidate interval value.

        Two guards keep this from firing on noise: enough baseline samples, and
        the value must exceed the absolute byte floor.  When the baseline is
        perfectly flat (std == 0) the z-score is undefined, so we fall back to a
        simple "value exceeds k x the baseline mean" test.
        """
        if not self.is_ready() or value < self.min_bytes:
            return False, self.zscore(value)
        std = self.std()
        if std <= 0:
            return value > self.mean() * self.k, 0.0
        z = (value - self.mean()) / std
        return z > self.k, z

    def add(self, value: float) -> None:
        """Record an interval value, trimming the window to ``window`` samples."""
        self._samples.append(float(value))
        if len(self._samples) > self.window:
            self._samples = self._samples[-self.window :]


class FirstSeenTracker:
    """Remembers which destination IPs have already been observed."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def __contains__(self, ip: str) -> bool:
        return ip in self._seen

    def add(self, ip: str) -> None:
        self._seen.add(ip)

    def update(self, ips: Iterable[str]) -> None:
        self._seen.update(ips)

    @property
    def seen(self) -> set[str]:
        return set(self._seen)


def _top_outbound_flow(flows: Iterable[Flow]) -> Optional[Flow]:
    outbound = [f for f in flows if f.bytes_out > 0]
    if not outbound:
        return None
    return max(outbound, key=lambda f: f.bytes_out)


def detect_interval(
    interval: IntervalStats,
    flows: Sequence[Flow],
    baseline: OutboundBaseline,
    tracker: FirstSeenTracker,
) -> list[Alert]:
    """Run all rules for one interval and return the alerts they produce.

    The baseline is *updated* by this function (call it once per interval).
    """
    alerts: list[Alert] = []
    timestamp = interval.timestamp

    # -- Rule 1: volumetric --------------------------------------------------
    is_anomaly, z = baseline.is_anomalous(interval.bytes_out)
    if is_anomaly:
        top = _top_outbound_flow(flows)
        alerts.append(
            Alert(
                timestamp=timestamp,
                reason=(
                    f"Volumetric outbound anomaly: {interval.bytes_out} bytes in one "
                    f"interval exceeds baseline mean + {baseline.k}*std (z={z:.2f})."
                ),
                severity=severity_from(z, interval.bytes_out),
                bytes=int(interval.bytes_out),
                dst_ip=top.dst_ip if top else None,
                dst_port=top.dst_port if top else None,
                zscore=round(z, 2),
            )
        )

    # -- Rules 2 & 3: per-flow checks (external destinations only) ----------
    for flow in flows:
        if flow.bytes_out <= 0:
            continue

        # Rule 4: purely-internal conversations are never "external" traffic.
        both_private = is_private(flow.src_ip) and is_private(flow.dst_ip)

        # Rule 3: suspicious port watchlist (external traffic only, so that an
        # internal SMB/file share on port 445 is not flagged).
        if is_suspicious_port(flow.dst_port) and not both_private:
            alerts.append(
                Alert(
                    timestamp=timestamp,
                    reason=f"Outbound traffic to suspicious port {flow.dst_port} ({flow.protocol}).",
                    severity=severity_from(None, flow.bytes_out),
                    bytes=int(flow.bytes_out),
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    zscore=None,
                )
            )

        # Rule 2: first-seen external destination (public IPs only).
        if is_public(flow.dst_ip) and flow.dst_ip not in tracker and flow.bytes_out >= config.FIRST_SEEN_MIN_BYTES:
            alerts.append(
                Alert(
                    timestamp=timestamp,
                    reason=(
                        f"First-seen external destination {flow.dst_ip} received "
                        f"{flow.bytes_out} outbound bytes."
                    ),
                    severity=severity_from(None, flow.bytes_out),
                    bytes=int(flow.bytes_out),
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    zscore=None,
                )
            )

    # Remember every external destination we just saw so "first-seen" only fires once.
    tracker.update(f.dst_ip for f in flows if f.bytes_out > 0 and is_public(f.dst_ip))

    # The current interval joins the baseline for future comparisons.
    baseline.add(interval.bytes_out)

    return alerts


def classify_flow_risk(flow: Flow, flagged_dsts: Iterable[str]) -> str:
    """Risk label for a single flow's network_event row.

    HIGH if the flow's destination was flagged by a high-severity alert, MEDIUM
    for suspicious ports, otherwise LOW.
    """
    if flow.dst_ip in set(flagged_dsts):
        return "HIGH"
    both_private = is_private(flow.src_ip) and is_private(flow.dst_ip)
    if is_suspicious_port(flow.dst_port) and not both_private:
        return "MEDIUM"
    return "LOW"
