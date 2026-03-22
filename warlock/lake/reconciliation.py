"""Reconciliation between OLTP and lake.

Compares row counts between OLTP tables and lake Parquet files.
Alerts if drift exceeds a configurable threshold (default 0.1%).
Intended for nightly or on-demand verification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Default drift threshold: 0.1%
DEFAULT_DRIFT_THRESHOLD = 0.001


@dataclass
class TableComparison:
    """Row count comparison for a single table."""

    table: str
    oltp_count: int
    lake_count: int

    @property
    def drift(self) -> float:
        """Absolute drift as a fraction. 0.0 = perfect match."""
        if self.oltp_count == 0:
            return 0.0 if self.lake_count == 0 else 1.0
        return abs(self.oltp_count - self.lake_count) / self.oltp_count

    @property
    def drift_pct(self) -> float:
        """Drift as a percentage."""
        return self.drift * 100.0

    @property
    def match(self) -> bool:
        """True if counts are identical."""
        return self.oltp_count == self.lake_count


@dataclass
class ReconciliationResult:
    """Result of a full reconciliation run."""

    comparisons: list[TableComparison] = field(default_factory=list)
    threshold: float = DEFAULT_DRIFT_THRESHOLD

    @property
    def passed(self) -> bool:
        """True if all tables are within the drift threshold."""
        return all(c.drift <= self.threshold for c in self.comparisons)

    @property
    def drifted(self) -> list[TableComparison]:
        """Tables that exceed the drift threshold."""
        return [c for c in self.comparisons if c.drift > self.threshold]


def _count_oltp_rows(session: Any) -> dict[str, int]:
    """Count rows in each OLTP pipeline table."""
    from sqlalchemy import func

    from warlock.db.models import (
        ConnectorRun,
        ControlMapping,
        ControlResult,
        Finding,
        RawEvent,
    )

    counts: dict[str, int] = {}
    for label, model in [
        ("raw_events", RawEvent),
        ("findings", Finding),
        ("control_mappings", ControlMapping),
        ("control_results", ControlResult),
        ("connector_runs", ConnectorRun),
    ]:
        counts[label] = session.query(func.count(model.id)).scalar() or 0

    return counts


def _count_lake_rows(lake_path: str) -> dict[str, int]:
    """Count rows in each lake zone by reading Parquet files.

    Uses DuckDB for efficient Parquet row counting.
    """
    counts: dict[str, int] = {
        "raw_events": 0,
        "findings": 0,
        "control_mappings": 0,
        "control_results": 0,
        "connector_runs": 0,
    }

    base = Path(lake_path)

    # Map zone paths to count keys
    zone_globs = {
        "raw_events": "raw/**/*.parquet",
        "findings": "enrichment/**/*.parquet",
        "control_results": "curated/control_results/**/*.parquet",
        "control_mappings": "curated/control_mappings/**/*.parquet",
        "connector_runs": "curated/connector_runs/**/*.parquet",
    }

    try:
        from warlock.lake.query import LakeQueryEngine

        engine = LakeQueryEngine(lake_path)
        try:
            for key, glob_pattern in zone_globs.items():
                parquet_files = list(base.glob(glob_pattern))
                if not parquet_files:
                    continue
                glob_path = str(base / glob_pattern)
                try:
                    result = engine.query(
                        f"SELECT COUNT(*) as cnt FROM read_parquet('{glob_path}', union_by_name=true)"
                    )
                    if result:
                        counts[key] = result[0]["cnt"]
                except Exception:
                    log.debug("No parquet files found for %s", key)
        finally:
            engine.close()
    except ImportError:
        log.warning("DuckDB not available — lake row counts will be 0")

    return counts


def reconcile(
    session: Any,
    lake_path: str,
    threshold: float = DEFAULT_DRIFT_THRESHOLD,
) -> ReconciliationResult:
    """Compare OLTP vs lake row counts.

    Parameters
    ----------
    session:
        SQLAlchemy session for OLTP queries.
    lake_path:
        Root path for the lake directory structure.
    threshold:
        Maximum acceptable drift as a fraction (default 0.001 = 0.1%).

    Returns
    -------
    ReconciliationResult with per-table comparisons.
    """
    oltp_counts = _count_oltp_rows(session)
    lake_counts = _count_lake_rows(lake_path)

    result = ReconciliationResult(threshold=threshold)

    for table in [
        "raw_events",
        "findings",
        "control_mappings",
        "control_results",
        "connector_runs",
    ]:
        result.comparisons.append(
            TableComparison(
                table=table,
                oltp_count=oltp_counts.get(table, 0),
                lake_count=lake_counts.get(table, 0),
            )
        )

    status = "PASSED" if result.passed else "DRIFTED"
    log.info(
        "Reconciliation %s: %d/%d tables within %.1f%% threshold",
        status,
        len(result.comparisons) - len(result.drifted),
        len(result.comparisons),
        threshold * 100,
    )

    return result


def sample_hashes(oltp_hashes: dict[str, str], lake_hashes: dict[str, str]) -> list[dict]:
    """Compare SHA-256 hashes between OLTP and lake records.

    Args:
        oltp_hashes: dict of {record_id: sha256_hash} from OLTP
        lake_hashes: dict of {record_id: sha256_hash} from lake

    Returns:
        List of mismatched records with id, oltp_hash, lake_hash, reason.
    """
    mismatches = []
    for record_id, oltp_hash in oltp_hashes.items():
        lake_hash = lake_hashes.get(record_id)
        if lake_hash is None:
            mismatches.append(
                {
                    "id": record_id,
                    "oltp_hash": oltp_hash,
                    "lake_hash": None,
                    "reason": "missing_in_lake",
                }
            )
        elif oltp_hash != lake_hash:
            mismatches.append(
                {
                    "id": record_id,
                    "oltp_hash": oltp_hash,
                    "lake_hash": lake_hash,
                    "reason": "hash_mismatch",
                }
            )
    return mismatches
