"""ExfilTrace - Network Monitoring & Anomaly Detection module (Module 7).

Captures live traffic (TShark/PyShark) or simulated traffic, aggregates it into
flows, runs volumetric / first-seen / suspicious-port anomaly detection, stores
everything in SQLite with correlation-ready UTC timestamps, and exposes the
results through three Flask REST endpoints whose JSON matches the frontend
mock contract in ``src/data/mockData.js``.

Public helper for the correlation stage::

    from backend.network.correlation import get_events_in_window
"""

__all__ = ["config", "db", "detector", "capture", "api", "app", "serializers", "correlation"]
__version__ = "0.1.0"
