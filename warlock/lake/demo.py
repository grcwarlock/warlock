"""Local development lake initialization.

Creates the lake directory structure and writes sample Parquet files.
Used by demo_seed.py when WLK_LAKE_ENABLED=true.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def init_lake(lake_path: str) -> None:
    """Create the lake directory structure."""
    base = Path(lake_path)
    for zone in ("raw", "enrichment", "curated"):
        (base / zone).mkdir(parents=True, exist_ok=True)
    log.info("Lake initialized at %s", lake_path)


def write_sample_parquet(
    lake_path: str, table_name: str, data: dict[str, list[Any]]
) -> None:
    """Write a dict of columns as a Parquet file to the curated zone."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    base = Path(lake_path) / "curated" / table_name
    base.mkdir(parents=True, exist_ok=True)
    table = pa.table(data)
    pq.write_table(table, str(base / "data.parquet"))
    log.info("Wrote %d rows to %s", len(next(iter(data.values()))), base)
