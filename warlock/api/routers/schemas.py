"""Shared Pydantic response models used across multiple routers."""

from __future__ import annotations

import re as _re
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    limit: int
    offset: int


class MessageResponse(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _dt_str(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _escape_like(s: str) -> str:
    """Escape SQL LIKE wildcard characters."""
    return _re.sub(r"([%_\\])", r"\\\1", s)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"Invalid date format: {s}")
