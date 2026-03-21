"""DuckDB query engine for reading Parquet/Iceberg data from the lake.

DuckDB runs in-process (no server). It reads Parquet files directly
from local filesystem or object storage. No JVM dependency.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


class LakeQueryEngine:
    """Embedded DuckDB query engine for analytical queries over the lake."""

    def __init__(self, lake_path: str = "lake") -> None:
        import duckdb

        self._lake_path = lake_path
        self._conn = duckdb.connect()
        # httpfs extension only needed for S3/HTTP reads, not local filesystem
        if lake_path.startswith("s3://") or lake_path.startswith("http"):
            try:
                self._conn.execute("INSTALL httpfs; LOAD httpfs;")
            except Exception:
                log.warning("Failed to load httpfs extension — S3/HTTP reads unavailable")
        log.info("DuckDB lake query engine initialized (lake_path=%s)", lake_path)

    def query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """Execute a SQL query and return results as a list of dicts."""
        result = self._conn.execute(sql, params or [])
        columns = [desc[0] for desc in result.description]
        return [dict(zip(columns, row)) for row in result.fetchall()]

    def query_df(self, sql: str, params: list[Any] | None = None):
        """Execute a SQL query and return a PyArrow Table."""
        result = self._conn.execute(sql, params or [])
        return result.fetch_arrow_table()

    def close(self) -> None:
        """Close the DuckDB connection."""
        self._conn.close()
