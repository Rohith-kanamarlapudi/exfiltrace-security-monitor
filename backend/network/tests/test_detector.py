"""Unit tests for the anomaly detection rules."""

from __future__ import annotations

import importlib

import pytest

from backend.network import config, detector
from backend.network.detector import (
    Alert,
    FirstSeenTracker,
    Flow,
    IntervalStats,
    OutboundBaseline,
    classify_flow_risk,
    detect_interval,
    is_private,
    is_public,
    is_suspicious_port,
    severity_from,
    severity_to_risk,
)


def _interval(ts="2026-10-05T14:05:00Z", out=0, inc=0, packets=1):
    return IntervalStats(timestamp=ts, bytes_out=out, bytes_in=inc, packets=packets, active_connections=1)


# -- helpers ---------------------------------------------------------------
def test_is_private_and_public():
    assert is_private("192.168.1.57")
    assert is_private("10.0.0.5")
    assert is_private("127.0.0.1")
    assert is_public("203.0.113.58")
    assert is_public("8.8.8.8")
    assert not is_private("not-an-ip")


def test_suspicious_ports():
    assert is_suspicious_port(4444)
    assert is_suspicious_port(23)
    assert not is_suspicious_port(443)
    assert not is_suspicious_port(None)


def test_severity_and_risk_mapping():
    assert severity_from(None, 1_000) == "low"
    assert severity_from(None, config.SEVERITY_MEDIUM_BYTES) == "medium"
    assert severity_from(None, config.SEVERITY_HIGH_BYTES) == "high"
    assert severity_from(config.SEVERITY_HIGH_Z + 1, 1) == "high"
    assert severity_to_risk("high") == "HIGH"
    assert severity_to_risk("medium") == "MEDIUM"
    assert severity_to_risk("low") == "LOW"


# -- volumetric baseline ----------------------------------------------------
def test_baseline_not_ready_until_min_samples():
    baseline = OutboundBaseline(min_samples=5)
    for _ in range(4):
        baseline.add(1000)
    assert not baseline.is_ready()
    anomalous, _ = baseline.is_anomalous(10_000_000)
    assert anomalous is False


def test_volumetric_anomaly_fires_with_enough_samples():
    baseline = OutboundBaseline(min_samples=5)
    for i in range(20):
        baseline.add(1000 + (i % 5) * 40)  # realistic jitter so std > 0
    anomalous, z = baseline.is_anomalous(50_000_000)
    assert anomalous is True
    assert z > 3


def test_flat_baseline_uses_ratio_fallback():
    baseline = OutboundBaseline(min_samples=5)
    for _ in range(20):
        baseline.add(1000)
    anomalous, z = baseline.is_anomalous(50_000_000)
    assert anomalous is True
    assert z == 0.0  # undefined z reported as 0, severity comes from bytes


def test_minimum_absolute_bytes_guards_noise():
    baseline = OutboundBaseline(min_samples=5)
    for _ in range(20):
        baseline.add(100)
    # Huge z-score but far below the absolute floor -> not flagged.
    anomalous, _ = baseline.is_anomalous(10_000)
    assert anomalous is False


def test_detect_interval_volumetric_alert_is_high():
    baseline = OutboundBaseline()
    for _ in range(20):
        baseline.add(500)
    flow = Flow(src_ip="192.168.1.57", dst_ip="203.0.113.58", dst_port=443, protocol="HTTPS", bytes_out=50_000_000)
    alerts = detect_interval(_interval(out=50_000_000), [flow], baseline, FirstSeenTracker())
    assert any(a.severity == "high" for a in alerts)
    assert any(a.dst_ip == "203.0.113.58" for a in alerts)


# -- first-seen external ----------------------------------------------------
def test_first_seen_external_fires_once():
    baseline = OutboundBaseline()
    tracker = FirstSeenTracker()
    flow = Flow(src_ip="192.168.1.57", dst_ip="203.0.113.58", dst_port=443, protocol="HTTPS", bytes_out=5_000_000)

    first = [a for a in detect_interval(_interval(out=5_000_000), [flow], baseline, tracker) if "First-seen" in a.reason]
    assert len(first) == 1

    second = [a for a in detect_interval(_interval(out=5_000_000), [flow], baseline, tracker) if "First-seen" in a.reason]
    assert second == []


def test_private_destination_not_first_seen():
    tracker = FirstSeenTracker()
    flow = Flow(src_ip="192.168.1.57", dst_ip="192.168.1.10", dst_port=445, protocol="SMB", bytes_out=9_000_000)
    alerts = detect_interval(_interval(out=9_000_000), [flow], OutboundBaseline(), tracker)
    assert not any("First-seen" in a.reason for a in alerts)


# -- suspicious ports -------------------------------------------------------
def test_external_suspicious_port_flagged():
    flow = Flow(src_ip="192.168.1.57", dst_ip="198.51.100.23", dst_port=3389, protocol="TCP", bytes_out=740)
    alerts = detect_interval(_interval(out=740), [flow], OutboundBaseline(), FirstSeenTracker())
    assert any("suspicious port 3389" in a.reason for a in alerts)


def test_internal_smb_not_flagged():
    flow = Flow(src_ip="192.168.1.57", dst_ip="192.168.1.10", dst_port=445, protocol="SMB", bytes_out=250_000)
    alerts = detect_interval(_interval(out=250_000), [flow], OutboundBaseline(), FirstSeenTracker())
    assert not any("suspicious port" in a.reason for a in alerts)


def test_classify_flow_risk():
    flow = Flow(src_ip="192.168.1.57", dst_ip="203.0.113.58", dst_port=443, protocol="HTTPS", bytes_out=1)
    assert classify_flow_risk(flow, ["203.0.113.58"]) == "HIGH"
    suspicious = Flow(src_ip="192.168.1.57", dst_ip="8.8.8.8", dst_port=4444, protocol="TCP", bytes_out=1)
    assert classify_flow_risk(suspicious, []) == "MEDIUM"
    benign = Flow(src_ip="192.168.1.57", dst_ip="8.8.8.8", dst_port=443, protocol="HTTPS", bytes_out=1)
    assert classify_flow_risk(benign, []) == "LOW"


def test_alert_risk_property():
    assert Alert(timestamp="t", reason="r", severity="high").risk == "HIGH"
