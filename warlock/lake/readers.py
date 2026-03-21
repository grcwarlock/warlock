"""Lake-backed analytical query methods.

Each method is the DuckDB equivalent of an OLTP repository method.
Results are returned in the same format as the OLTP method to enable
transparent swapping via feature flags.

SECURITY: All user-supplied values use parameterized queries (?).
Glob paths are constructed from the internal lake_path.
ABAC: Methods accept allowed_frameworks / allowed_system_profiles for
scope filtering.  When None (default), no filtering is applied —
callers that enforce ABAC must pass the user's granted scopes.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _abac_clauses(
    allowed_frameworks: list[str] | None = None,
    allowed_system_profiles: list[str] | None = None,
    *,
    has_system_profile: bool = True,
) -> tuple[list[str], list[Any]]:
    """Build WHERE sub-clauses and params for ABAC scope filtering."""
    clauses: list[str] = []
    params: list[Any] = []
    if allowed_frameworks:
        placeholders = ", ".join("?" for _ in allowed_frameworks)
        clauses.append(f"framework IN ({placeholders})")
        params.extend(allowed_frameworks)
    if allowed_system_profiles and has_system_profile:
        placeholders = ", ".join("?" for _ in allowed_system_profiles)
        clauses.append(f"system_profile_id IN ({placeholders})")
        params.extend(allowed_system_profiles)
    return clauses, params


def _inject_where(
    existing_where: str | None,
    abac_clauses: list[str],
) -> str:
    """Merge ABAC clauses with an optional existing WHERE clause.

    *existing_where* should be the full ``WHERE ...`` fragment (including
    the keyword) or *None* when there is no pre-existing filter.
    """
    if not abac_clauses:
        return existing_where or ""
    abac_expr = " AND ".join(abac_clauses)
    if existing_where:
        # Strip leading "WHERE " and combine
        return f"{existing_where} AND {abac_expr}"
    return f"WHERE {abac_expr}"


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

    def dashboard_framework_summary(
        self,
        allowed_frameworks: list[str] | None = None,
        allowed_system_profiles: list[str] | None = None,
    ) -> list[tuple[str, str, int]]:
        glob = self._cr_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, allowed_system_profiles)
        where = _inject_where(None, abac_clauses)
        result = self._engine.query(
            f"""
            SELECT framework, status, COUNT(*) as cnt
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            GROUP BY framework, status
            ORDER BY framework, cnt DESC
        """,
            params or None,
        )
        return [(r["framework"], r["status"], r["cnt"]) for r in result]

    def coverage_by_status(
        self,
        framework: str = None,
        allowed_frameworks: list[str] | None = None,
        allowed_system_profiles: list[str] | None = None,
    ) -> list[tuple[str, str, int]]:
        glob = self._cr_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, allowed_system_profiles)

        base_where_parts: list[str] = []
        base_params: list[Any] = []
        if framework:
            base_where_parts.append("framework = ?")
            base_params.append(framework)

        all_parts = base_where_parts + abac_clauses
        where = ("WHERE " + " AND ".join(all_parts)) if all_parts else ""
        all_params = base_params + params

        result = self._engine.query(
            f"""
            SELECT framework, status, COUNT(*) as cnt
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            GROUP BY framework, status
            ORDER BY framework, status
        """,
            all_params or None,
        )
        return [(r["framework"], r["status"], r["cnt"]) for r in result]

    def distinct_frameworks(
        self,
        allowed_frameworks: list[str] | None = None,
    ) -> list[str]:
        glob = self._cr_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, has_system_profile=False)
        where = _inject_where(None, abac_clauses)
        result = self._engine.query(
            f"""
            SELECT DISTINCT framework
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            ORDER BY framework
        """,
            params or None,
        )
        return [r["framework"] for r in result]

    def top_non_compliant_risks(
        self,
        allowed_frameworks: list[str] | None = None,
        allowed_system_profiles: list[str] | None = None,
    ) -> list[dict]:
        glob = self._cr_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, allowed_system_profiles)
        where = _inject_where("WHERE status = 'non_compliant'", abac_clauses)
        result = self._engine.query(
            f"""
            SELECT framework, control_id, severity, COUNT(*) as cnt
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            GROUP BY framework, control_id, severity
            ORDER BY cnt DESC
            LIMIT 20
        """,
            params or None,
        )
        return result

    def last_assessed_at(
        self,
        allowed_frameworks: list[str] | None = None,
        allowed_system_profiles: list[str] | None = None,
    ) -> datetime | None:
        glob = self._cr_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, allowed_system_profiles)
        where = _inject_where(None, abac_clauses)
        result = self._engine.query(
            f"""
            SELECT MAX(assessed_at) as max_at
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
        """,
            params or None,
        )
        if result and result[0]["max_at"]:
            val = result[0]["max_at"]
            if isinstance(val, str):
                return datetime.fromisoformat(val)
            return val
        return None

    # --- ControlMappingRepository equivalents ---

    def list_frameworks(
        self,
        limit: int = 100,
        offset: int = 0,
        allowed_frameworks: list[str] | None = None,
    ) -> list[tuple[str, int]]:
        glob = self._cm_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, has_system_profile=False)
        where = _inject_where(None, abac_clauses)
        all_params = params + [limit, offset]
        result = self._engine.query(
            f"""
            SELECT framework, COUNT(DISTINCT control_id) as control_count
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            GROUP BY framework
            ORDER BY framework
            LIMIT ? OFFSET ?
        """,
            all_params,
        )
        return [(r["framework"], r["control_count"]) for r in result]

    def list_controls(
        self,
        framework_id: str,
        limit: int = 100,
        offset: int = 0,
        allowed_frameworks: list[str] | None = None,
    ) -> list[tuple]:
        glob = self._cm_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, has_system_profile=False)
        where = _inject_where("WHERE framework = ?", abac_clauses)
        all_params = [framework_id] + params + [limit, offset]
        result = self._engine.query(
            f"""
            SELECT control_id, control_family, mapping_method, COUNT(*) as mapping_count
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            GROUP BY control_id, control_family, mapping_method
            ORDER BY control_id
            LIMIT ? OFFSET ?
        """,
            all_params,
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

    def findings_by_severity(
        self,
        severity: str,
        limit: int = 100,
        allowed_frameworks: list[str] | None = None,
    ) -> list[dict]:
        glob = self._findings_glob()
        abac_clauses, params = _abac_clauses(allowed_frameworks, has_system_profile=False)
        where = _inject_where("WHERE severity = ?", abac_clauses)
        all_params = [severity] + params + [limit]
        result = self._engine.query(
            f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            ORDER BY observed_at DESC
            LIMIT ?
        """,
            all_params,
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

    def latest_snapshot_date(
        self,
        allowed_frameworks: list[str] | None = None,
        allowed_system_profiles: list[str] | None = None,
    ) -> datetime | None:
        """Latest snapshot date from lake posture data."""
        glob = self._posture_glob()
        if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
            return None
        abac_clauses, params = _abac_clauses(allowed_frameworks, allowed_system_profiles)
        where = _inject_where(None, abac_clauses)
        result = self._engine.query(
            f"""
            SELECT MAX(snapshot_date) as max_date
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
        """,
            params or None,
        )
        if result and result[0]["max_date"]:
            val = result[0]["max_date"]
            return datetime.fromisoformat(str(val)) if isinstance(val, str) else val
        return None

    def framework_avg_scores_at(
        self,
        snapshot_date=None,
        allowed_frameworks: list[str] | None = None,
        allowed_system_profiles: list[str] | None = None,
    ) -> list[tuple[str, float]]:
        """Average posture score per framework."""
        glob = self._posture_glob()
        if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
            return []

        base_parts: list[str] = []
        base_params: list[Any] = []
        if snapshot_date:
            base_parts.append("snapshot_date = ?")
            base_params.append(str(snapshot_date))

        abac_clauses, abac_params = _abac_clauses(allowed_frameworks, allowed_system_profiles)
        all_parts = base_parts + abac_clauses
        where = ("WHERE " + " AND ".join(all_parts)) if all_parts else ""
        all_params = base_params + abac_params

        result = self._engine.query(
            f"""
            SELECT framework, AVG(CAST(posture_score AS DOUBLE)) as avg_score
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            GROUP BY framework ORDER BY framework
        """,
            all_params or None,
        )
        return [(r["framework"], float(r["avg_score"])) for r in result]

    def effectiveness_latest(
        self,
        framework: str = None,
        days: int = 30,
        allowed_frameworks: list[str] | None = None,
        allowed_system_profiles: list[str] | None = None,
    ) -> list[dict]:
        """Control effectiveness from posture snapshots."""
        glob = self._posture_glob()
        if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
            return []

        base_parts: list[str] = []
        base_params: list[Any] = []
        if framework:
            base_parts.append("framework = ?")
            base_params.append(framework)

        abac_clauses, abac_params = _abac_clauses(allowed_frameworks, allowed_system_profiles)
        all_parts = base_parts + abac_clauses
        where = ("WHERE " + " AND ".join(all_parts)) if all_parts else ""
        all_params = base_params + abac_params

        result = self._engine.query(
            f"""
            SELECT framework, control_id, status,
                   CAST(posture_score AS DOUBLE) as posture_score, snapshot_date
            FROM read_parquet('{glob}', union_by_name=true)
            {where}
            ORDER BY snapshot_date DESC
        """,
            all_params or None,
        )
        return result
