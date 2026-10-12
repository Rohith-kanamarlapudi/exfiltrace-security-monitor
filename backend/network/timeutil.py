"""UTC time helpers.

Every timestamp that leaves this module is an ISO 8601 UTC string
(``YYYY-MM-DDTHH:MM:SSZ``).  Correlation with the USB and file modules depends
on the whole team using the same convention, so all conversions go through here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

#: Canonical wire format for the whole project.
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC ``datetime``."""
    return datetime.now(timezone.utc)


def to_iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """Serialise a ``datetime`` to an ISO 8601 UTC string.

    Naive datetimes are assumed to already be UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(ISO_FORMAT)


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 string (with or without ``Z``) into an aware UTC datetime."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso_now() -> str:
    """Current time as an ISO 8601 UTC string."""
    return to_iso_utc(utcnow())


def bucket_start(dt: datetime, seconds: int) -> datetime:
    """Floor ``dt`` to a fixed-size bucket of ``seconds`` starting at the UTC epoch."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    epoch = int(dt.timestamp())
    floored = epoch - (epoch % seconds)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def bucket_label(dt: datetime) -> str:
    """Return the ``HH:MM`` label (UTC) used by the traffic-over-time chart."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%H:%M")


def add_seconds(dt: datetime, seconds: float) -> datetime:
    """Return ``dt`` shifted by ``seconds`` (may be negative)."""
    return dt + timedelta(seconds=seconds)
