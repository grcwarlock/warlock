"""Materialized aggregation tables for the analytics layer.

Pre-computed summaries written to the curated zone after each
pipeline run. Dashboards read from these instead of scanning all results.

Tables:
- agg_framework_posture: per-framework compliance summary
- agg_control_family_posture: per-control-family within each framework
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def refresh_aggregations(lake_path: str) -> dict[str, int]:
    """Refresh all materialized aggregation tables. Returns row counts."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    from warlock.lake.query import LakeQueryEngine

    base = Path(lake_path)
    counts: dict[str, int] = {}

    # Check if any source parquet files exist before opening DuckDB
    cr_base = base / "curated" / "control_results"
    cm_base = base / "curated" / "control_mappings"
    cr_files = list(cr_base.rglob("*.parquet")) if cr_base.exists() else []
    cm_files = list(cm_base.rglob("*.parquet")) if cm_base.exists() else []

    if not cr_files:
        log.info("No control_results parquet files found — skipping aggregation refresh")
        return counts

    engine = LakeQueryEngine(lake_path)
    now = datetime.now(timezone.utc).isoformat()

    try:
        cr_glob = str(cr_base / "**" / "*.parquet")
        cm_glob = str(cm_base / "**" / "*.parquet")

        # agg_framework_posture
        result = engine.query(f"""
            SELECT
                framework,
                COUNT(*) as total_results,
                COUNT(CASE WHEN status = 'compliant' THEN 1 END) as compliant_count,
                COUNT(CASE WHEN status = 'non_compliant' THEN 1 END) as non_compliant_count,
                COUNT(CASE WHEN status = 'partial' THEN 1 END) as partial_count,
                COUNT(CASE WHEN status = 'not_assessed' THEN 1 END) as not_assessed_count,
                ROUND(COUNT(CASE WHEN status = 'compliant' THEN 1 END) * 100.0 / COUNT(*), 1) as compliance_pct,
                MAX(assessed_at) as last_assessed,
                '{now}' as refreshed_at
            FROM read_parquet('{cr_glob}', union_by_name=true)
            GROUP BY framework
            ORDER BY framework
        """)

        if result:
            out_dir = base / "curated" / "agg_framework_posture"
            out_dir.mkdir(parents=True, exist_ok=True)
            table = pa.table({k: [r[k] for r in result] for k in result[0]})
            pq.write_table(table, str(out_dir / "latest.parquet"))
            counts["agg_framework_posture"] = len(result)
            log.info("Refreshed agg_framework_posture: %d rows", len(result))

        # agg_control_family_posture — only if both cr and cm files exist
        if cm_files:
            result = engine.query(f"""
                SELECT
                    cr.framework,
                    cm.control_family,
                    COUNT(*) as total_results,
                    COUNT(CASE WHEN cr.status = 'compliant' THEN 1 END) as compliant_count,
                    COUNT(CASE WHEN cr.status = 'non_compliant' THEN 1 END) as non_compliant_count,
                    ROUND(COUNT(CASE WHEN cr.status = 'compliant' THEN 1 END) * 100.0 / COUNT(*), 1) as compliance_pct,
                    '{now}' as refreshed_at
                FROM read_parquet('{cr_glob}', union_by_name=true) cr
                JOIN read_parquet('{cm_glob}', union_by_name=true) cm
                    ON cr.control_id = cm.control_id
                GROUP BY cr.framework, cm.control_family
                ORDER BY cr.framework, cm.control_family
            """)

            if result:
                out_dir = base / "curated" / "agg_control_family_posture"
                out_dir.mkdir(parents=True, exist_ok=True)
                table = pa.table({k: [r[k] for r in result] for k in result[0]})
                pq.write_table(table, str(out_dir / "latest.parquet"))
                counts["agg_control_family_posture"] = len(result)
                log.info("Refreshed agg_control_family_posture: %d rows", len(result))

    finally:
        engine.close()

    return counts
