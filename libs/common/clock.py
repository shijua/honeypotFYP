"""Time helpers shared across services.

Keeping one UTC helper avoids mixing naive and timezone-aware timestamps.
"""

from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)

