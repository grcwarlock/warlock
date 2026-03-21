"""Lake-backed analytical query methods.

Each method is the DuckDB equivalent of an OLTP repository method.
Results are returned in the same format as the OLTP method to enable
transparent swapping via feature flags.

SECURITY: All user-supplied values use parameterized queries (?).
Glob paths are constructed from the internal lake_path.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class LakeReaders:
    """DuckDB-backed readers for analytical queries over the lake."""

    def __init__(self, lake_path: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        self._lake_path = lake_path
        self._engine = LakeQueryEngine(lake_path)
        self._base = Path(lake_path)

    def close(self) -> None:
        self._engine.close()

    def _cr_glob(self) -> str:
        return str(self._base / "curated" / "control_results" / "**" / "*.parquet")

    def _cm_glob(self) -> str:
        return str(self._base / "curated" / "control_mappings" / "**" / "*.parquet")

    def _findings_glob(self) -> str:
        return str(self._base / "enrichment" / "**" / "*.parquet")

    def _connector_glob(self) -> str:
        return str(self._base / "curated" / "connector_runs" / "**" / "*.parquet")

    # --- ControlResultRepository equivalents ---

    def dashboard_framework_summary(self) -> list[tuple[str, str, int]]:
        glob = self._cr_glob()
        result = self._engine.query(f"""
            SELECT framework, status, COUNT(*) as cnt
            FROM read_parquet('{glob}', union_by_name=true)
            GROUP BY framework, status
            ORDER BY framework, cnt DESC
        """)
        return [(r["framework"], r["status"], r["cnt"]) for r in result]

    def coverage_by_status(self, framework: str = None) -> list[tuple[str, str, int]]:
        glob = self._cr_glob()
        if framework:
            result = self._engine.query(
                f"""
                SELECT framework, status, COUNT(*) as cnt
                FROM read_parquet('{glob}', union_by_name=true)
                WHERE framework = ?
                GROUP BY framework, status
                ORDER BY framework, status
            """,
                [framework],
            )
        else:
            result = self._engine.query(f"""
                SELECT framework, status, COUNT(*) as cnt
                FROM read_parquet('{glob}', union_by_name=true)
                GROUP BY framework, status
                ORDER BY framework, status
            """)
        return [(r["framework"], r["status"], r["cnt"]) for r in result]

    def distinct_frameworks(self) -> list[str]:
        glob = self._cr_glob()
        result = self._engine.query(f"""
            SELECT DISTINCT framework
            FROM read_parquet('{glob}', union_by_name=true)
            ORDER BY framework
        """)
        return [r["framework"] for r in result]

    def top_non_compliant_risks(self) -> list[dict]:
        glob = self._cr_glob()
        result = self._engine.query(f"""
            SELECT framework, control_id, severity, COUNT(*) as cnt
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE status = 'non_compliant'
            GROUP BY framework, control_id, severity
            ORDER BY cnt DESC
            LIMIT 20
        """)
        return result

    def last_assessed_at(self) -> datetime | None:
        glob = self._cr_glob()
        result = self._engine.query(f"""
            SELECT MAX(assessed_at) as max_at
            FROM read_parquet('{glob}', union_by_name=true)
        """)
        if result and result[0]["max_at"]:
            val = result[0]["max_at"]
            if isinstance(val, str):
                return datetime.fromisoformat(val)
            return val
        return None

    # --- ControlMappingRepository equivalents ---

    def list_frameworks(
        self, limit: int = 100, offset: int = 0
    ) -> list[tuple[str, int]]:
        glob = self._cm_glob()
        result = self._engine.query(
            f"""
            SELECT framework, COUNT(DISTINCT control_id) as control_count
            FROM read_parquet('{glob}', union_by_name=true)
            GROUP BY framework
            ORDER BY framework
            LIMIT ? OFFSET ?
        """,
            [limit, offset],
        )
        return [(r["framework"], r["control_count"]) for r in result]

    def list_controls(
        self, framework_id: str, limit: int = 100, offset: int = 0
    ) -> list[tuple]:
        glob = self._cm_glob()
        result = self._engine.query(
            f"""
            SELECT control_id, control_family, mapping_method, COUNT(*) as mapping_count
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE framework = ?
            GROUP BY control_id, control_family, mapping_method
            ORDER BY control_id
            LIMIT ? OFFSET ?
        """,
            [framework_id, limit, offset],
        )
        return [
            (r["control_id"], r["control_family"], r["mapping_method"], r["mapping_count"])
            for r in result
        ]

    # --- ConnectorRunRepository equivalents ---

    def total_event_count(self) -> int:
        glob = self._connector_glob()
        result = self._engine.query(f"""
            SELECT COALESCE(SUM(event_count), 0) as total
            FROM read_parquet('{glob}', union_by_name=true)
        """)
        return int(result[0]["total"]) if result else 0

    def latest_per_connector(self) -> list[dict]:
        glob = self._connector_glob()
        result = self._engine.query(f"""
            WITH ranked AS (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY connector_name ORDER BY started_at DESC
                ) as rn
                FROM read_parquet('{glob}', union_by_name=true)
            )
            SELECT * EXCLUDE(rn) FROM ranked WHERE rn = 1
            ORDER BY connector_name
        """)
        return result

    def latest_per_provider(self) -> list[dict]:
        glob = self._connector_glob()
        result = self._engine.query(f"""
            WITH ranked AS (
                SELECT *, ROW_NUMBER() OVER (
                    PARTITION BY provider ORDER BY started_at DESC
                ) as rn
                FROM read_parquet('{glob}', union_by_name=true)
            )
            SELECT * EXCLUDE(rn) FROM ranked WHERE rn = 1
            ORDER BY provider
        """)
        return result

    # --- FindingRepository equivalents ---

    def findings_by_severity(self, severity: str, limit: int = 100) -> list[dict]:
        glob = self._findings_glob()
        result = self._engine.query(
            f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE severity = ?
            ORDER BY observed_at DESC
            LIMIT ?
        """,
            [severity, limit],
        )
        return result

    def findings_by_source(self, source: str, limit: int = 100) -> list[dict]:
        glob = self._findings_glob()
        result = self._engine.query(
            f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE source = ?
            ORDER BY observed_at DESC
            LIMIT ?
        """,
            [source, limit],
        )
        return result

    # --- PostureSnapshotRepository equivalents ---

    def _posture_glob(self) -> str:
        return str(self._base / "curated" / "posture_snapshots" / "**" / "*.parquet")

    def latest_snapshot_date(self) -> datetime | None:
        """Latest snapshot date from lake posture data."""
        glob = self._posture_glob()
        if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
            return None
        result = self._engine.query(f"""
            SELECT MAX(snapshot_date) as max_date
            FROM read_parquet('{glob}', union_by_name=true)
        """)
        if result and result[0]["max_date"]:
            val = result[0]["max_date"]
            return datetime.fromisoformat(str(val)) if isinstance(val, str) else val
        return None

    def framework_avg_scores_at(self, snapshot_date=None) -> list[tuple[str, float]]:
        """Average posture score per framework."""
        glob = self._posture_glob()
        if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
            return []
        if snapshot_date:
            result = self._engine.query(
                f"""
                SELECT framework, AVG(CAST(posture_score AS DOUBLE)) as avg_score
                FROM read_parquet('{glob}', union_by_name=true)
                WHERE snapshot_date = ?
                GROUP BY framework ORDER BY framework
            """,
                [str(snapshot_date)],
            )
        else:
            result = self._engine.query(f"""
                SELECT framework, AVG(CAST(posture_score AS DOUBLE)) as avg_score
                FROM read_parquet('{glob}', union_by_name=true)
                GROUP BY framework ORDER BY framework
            """)
        return [(r["framework"], float(r["avg_score"])) for r in result]

    def effectiveness_latest(
        self, framework: str = None, days: int = 30
    ) -> list[dict]:
        """Control effectiveness from posture snapshots."""
        glob = self._posture_glob()
        if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
            return []
        if framework:
            result = self._engine.query(
                f"""
                SELECT framework, control_id, status,
                       CAST(posture_score AS DOUBLE) as posture_score, snapshot_date
                FROM read_parquet('{glob}', union_by_name=true)
                WHERE framework = ?
                ORDER BY snapshot_date DESC
            """,
                [framework],
            )
        else:
            result = self._engine.query(f"""
                SELECT framework, control_id, status,
                       CAST(posture_score AS DOUBLE) as posture_score, snapshot_date
                FROM read_parquet('{glob}', union_by_name=true)
                ORDER BY snapshot_date DESC
            """)
        return result
