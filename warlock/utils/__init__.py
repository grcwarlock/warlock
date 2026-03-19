"""Shared utility functions for the Warlock GRC platform."""

from __future__ import annotations

from datetime import datetime, timezone


def ensure_aware(dt: datetime | None) -> datetime | None:
    """Ensure a datetime is timezone-aware (assume UTC if naive)."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
