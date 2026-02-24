from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)

