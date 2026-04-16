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
        # N25 fix: only load httpfs extension when lake_path is an explicit
        # remote scheme AND the operator has opted in via lake_remote_enabled.
        # Without the gate, an operator-controlled lake_path could become an
        # SSRF primitive (DuckDB httpfs reads any URL passed to subsequent
        # SQL queries).
        if lake_path.startswith(("s3://", "http://", "https://")):
            try:
                from warlock.config import get_settings

                if not getattr(get_settings(), "lake_remote_enabled", False):
                    log.warning(
                        "lake_path is remote (%s) but WLK_LAKE_REMOTE_ENABLED is False — "
                        "refusing to load httpfs extension. Set lake_remote_enabled=True "
                        "to opt in.",
                        lake_path,
                    )
                else:
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
