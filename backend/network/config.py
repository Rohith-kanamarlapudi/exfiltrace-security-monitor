"""Central configuration for the network monitoring module.

Everything tunable lives here so thresholds can be explained in the lab report
without hunting through the code.  Values can be overridden with environment
variables (handy for tests and for running the demo without touching the repo).
"""

from __future__ import annotations

import ipaddress
import os
from typing import Tuple

# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exfiltrace_network.db")


def get_db_path() -> str:
    """Return the SQLite path, overridable via ``EXFILTRACE_NETWORK_DB``."""
    return os.environ.get("EXFILTRACE_NETWORK_DB") or _DEFAULT_DB


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------
#: Interface to sniff. ``None`` lets PyShark/tshark pick a default; on macOS the
#: usual value is ``en0``, on Windows a name like ``\\Device\\NPF_{GUID}``.
CAPTURE_INTERFACE: str | None = os.environ.get("EXFILTRACE_IFACE") or None

#: Aggregation interval for live stats/detection, in seconds.
STATS_INTERVAL_SECONDS: int = int(os.environ.get("EXFILTRACE_INTERVAL", "10"))

#: Bucket size for the /network/traffic endpoint (30 minutes, matching the mock).
TRAFFIC_BUCKET_SECONDS: int = int(os.environ.get("EXFILTRACE_TRAFFIC_BUCKET", str(30 * 60)))

#: A connection is "active" if its last packet is within this many seconds of the
#: most recent observed activity.  Relative (not wall-clock) so seeded/demo data works.
ACTIVE_CONNECTION_WINDOW_SECONDS: int = 120

#: Flows smaller than this are not promoted to network_events.
MIN_EVENT_BYTES: int = int(os.environ.get("EXFILTRACE_MIN_EVENT_BYTES", "1"))

# --------------------------------------------------------------------------
# Anomaly detection
# --------------------------------------------------------------------------
#: Volumetric rule: flag when an interval's outbound bytes exceed mean + k*std.
ANOMALY_K: float = float(os.environ.get("EXFILTRACE_ANOMALY_K", "3.0"))

#: Number of intervals required before the volumetric rule is trusted.
MIN_BASELINE_SAMPLES: int = int(os.environ.get("EXFILTRACE_MIN_BASELINE", "10"))

#: Cap the rolling baseline window (older samples are dropped).
BASELINE_WINDOW: int = int(os.environ.get("EXFILTRACE_BASELINE_WINDOW", "180"))

#: Ignore volumetric flags below this many bytes in a single interval (noise guard).
MIN_ABSOLUTE_BYTES: int = int(os.environ.get("EXFILTRACE_MIN_ABSOLUTE_BYTES", "5000000"))

#: First-seen rule: outbound bytes to a brand-new public IP above this are notable.
FIRST_SEEN_MIN_BYTES: int = int(os.environ.get("EXFILTRACE_FIRST_SEEN_BYTES", "1000000"))

#: Ports commonly used by exfiltration / remote-control tooling.
SUSPICIOUS_PORTS: Tuple[int, ...] = (21, 23, 445, 3389, 4444, 6667, 9001, 31337)

#: Severity mapping thresholds (see detector.severity_from).
SEVERITY_MEDIUM_BYTES: int = 10_000_000
SEVERITY_HIGH_BYTES: int = 40_000_000
SEVERITY_MEDIUM_Z: float = 4.0
SEVERITY_HIGH_Z: float = 5.0

#: Rules 2-4 only apply to "external" destinations; these ranges are treated as local.
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# --------------------------------------------------------------------------
# REST API
# --------------------------------------------------------------------------
API_HOST: str = os.environ.get("EXFILTRACE_API_HOST", "0.0.0.0")
API_PORT: int = int(os.environ.get("EXFILTRACE_API_PORT", "5000"))

# --------------------------------------------------------------------------
# Simulation
# --------------------------------------------------------------------------
#: Simulated capture emits one interval of synthetic traffic every N seconds.
SIM_INTERVAL_SECONDS: float = float(os.environ.get("EXFILTRACE_SIM_INTERVAL", "1.0"))

#: Local host identity used to decide direction and to build synthetic flows.
SIM_LOCAL_IP: str = os.environ.get("EXFILTRACE_SIM_LOCAL_IP", "192.168.1.57")
