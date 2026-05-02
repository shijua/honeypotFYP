"""Time helpers shared across services.

Keeping one UTC helper avoids mixing naive and timezone-aware timestamps.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)


def utc_aware(value: datetime) -> datetime:
    """Normalize naive and aware datetimes to comparable UTC-aware values."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_iso_datetime(value: object) -> datetime | None:
    """Parse a JSON ISO datetime into a UTC-aware datetime."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return utc_aware(parsed)
