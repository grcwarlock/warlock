"""Shared utilities for lake modules.

Centralizes functions used by multiple lake modules to avoid duplication.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def model_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a SQLAlchemy model instance to a dict.

    Handles JSON fields by serializing with sort_keys=True for hash integrity.
    Uses the same serialization as OLTP to preserve SHA-256 consistency.
    """
    d: dict[str, Any] = {}
    for col in obj.__table__.columns:
        val = getattr(obj, col.name, None)
        if isinstance(val, (dict, list)):
            val = json.dumps(val, sort_keys=True, default=str)
        d[col.name] = val
    return d


def today_partition() -> str:
    """Return today's date as YYYY-MM-DD for Parquet partitioning."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def ensure_dir(path: Path) -> None:
    """Create directory and parents if they don't exist."""
    path.mkdir(parents=True, exist_ok=True)


def serialize_json_field(value: Any) -> str:
    """Serialize a JSON-capable field to a deterministic string.

    Uses sort_keys=True and default=str to preserve SHA-256 hash integrity
    across OLTP and lake representations.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, default=str)
