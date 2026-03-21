"""Iceberg catalog abstraction.

Supports:
- SQLite catalog (dev/on-prem) — PyIceberg native, no server needed
- REST catalog (cloud) — connects to any Iceberg REST catalog service
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


def create_catalog(catalog_type: str, uri: str, **kwargs: Any):
    """Factory for creating Iceberg catalog instances.

    Args:
        catalog_type: "sqlite" or "rest"
        uri: SQLite DB path (for sqlite) or REST catalog URL (for rest)
    """
    from pyiceberg.catalog import load_catalog

    if catalog_type == "sqlite":
        return load_catalog(
            "warlock",
            **{
                "type": "sql",
                "uri": f"sqlite:///{uri}",
                **kwargs,
            },
        )
    elif catalog_type == "rest":
        if not uri:
            raise ValueError("REST catalog URL required")
        return load_catalog(
            "warlock",
            **{
                "type": "rest",
                "uri": uri,
                **kwargs,
            },
        )
    else:
        raise ValueError(f"Unknown catalog type: {catalog_type}. Use 'sqlite' or 'rest'.")
