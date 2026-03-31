"""Batch AI control assessment over the curated zone.

Reads control results from the lake, groups by (framework, control_id),
computes aggregate status via majority voting, and writes results back
to the lake curated zone.

This is Phase 3's core innovation: AI moves from seeing one finding at
a time (pipeline Stage 4) to reasoning over all evidence for a control.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


def aggregate_control_statuses(lake_path: str) -> list[dict[str, Any]]:
    """Compute aggregate status per control from lake data.

    Groups all control results by (framework, control_id) and determines
    an aggregate status via majority voting.
    """
    from pathlib import Path

    from warlock.lake.query import LakeQueryEngine

    engine = LakeQueryEngine(lake_path)
    base = Path(lake_path)
    cr_glob = str(base / "curated" / "control_results" / "**" / "*.parquet")

    try:
        # Check if any parquet files exist
        if not list(base.glob("curated/control_results/**/*.parquet")):
            return []

        result = engine.query(f"""
            SELECT
                framework,
                control_id,
                COUNT(*) as total_assessments,
                COUNT(CASE WHEN status = 'compliant' THEN 1 END) as compliant_count,
                COUNT(CASE WHEN status = 'non_compliant' THEN 1 END) as non_compliant_count,
                COUNT(CASE WHEN status = 'partial' THEN 1 END) as partial_count,
                COUNT(CASE WHEN status = 'not_assessed' THEN 1 END) as not_assessed_count,
                MAX(assessed_at) as last_assessed
            FROM read_parquet('{cr_glob}', union_by_name=true)
            GROUP BY framework, control_id
            ORDER BY framework, control_id
        """)
    finally:
        engine.close()

    aggregates = []
    for row in result:
        total = row["total_assessments"]
        status = _determine_aggregate_status(
            row["compliant_count"],
            row["non_compliant_count"],
            row["partial_count"],
            row["not_assessed_count"],
            total,
        )
        aggregates.append(
            {
                "framework": row["framework"],
                "control_id": row["control_id"],
                "aggregate_status": status,
                "total_assessments": total,
                "compliant_count": row["compliant_count"],
                "non_compliant_count": row["non_compliant_count"],
                "partial_count": row["partial_count"],
                "not_assessed_count": row["not_assessed_count"],
                "last_assessed": str(row["last_assessed"] or ""),
                "computed_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    return aggregates


def _determine_aggregate_status(
    compliant: int, non_compliant: int, partial: int, not_assessed: int, total: int
) -> str:
    """Majority voting for aggregate control status."""
    if total == 0:
        return "not_assessed"
    if compliant == total:
        return "compliant"
    if non_compliant == total:
        return "non_compliant"
    if compliant > total / 2:
        return "compliant"
    if non_compliant > total / 2:
        return "non_compliant"
    return "partial"


def write_aggregate_assessments(lake_path: str, aggregates: list[dict]) -> int:
    """Write aggregate assessments to curated zone. Returns row count."""
    if not aggregates:
        return 0

    from pathlib import Path

    import pyarrow as pa
    import pyarrow.parquet as pq

    base = Path(lake_path) / "curated" / "aggregate_control_assessments"
    base.mkdir(parents=True, exist_ok=True)

    table = pa.table({k: [str(r[k]) for r in aggregates] for k in aggregates[0]})
    pq.write_table(table, str(base / "latest.parquet"))
    log.info("Wrote %d aggregate assessments to %s", len(aggregates), base)
    return len(aggregates)
