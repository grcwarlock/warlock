"""DuckDB Feasibility Spike — Phase 0 Validation.

Generates Parquet files at 10x demo scale and benchmarks the 5 hardest
compliance queries. Target: all queries < 500ms.

Observed latencies (2026-03-21, Apple Silicon, local filesystem):
  Query 1 — Dashboard GROUP BY framework+status:   15.7 ms (70 rows)
  Query 2 — Posture trend AVG by framework+date:   19.5 ms (2534 rows)
  Query 3 — Coverage summary with CTE + JOIN:      10.7 ms (70 rows)
  Query 4 — Findings with window pagination:       27.7 ms (100 rows, 2190 total)
  Query 5 — Cross-framework drift detection:      145.2 ms (2269 drifted controls)
  All queries well under 500ms limit. Phase 2 migration baseline established.
"""

import time
import uuid
from datetime import datetime, timezone, timedelta
import pytest

pytest.importorskip("pyarrow")

FRAMEWORKS = [
    "nist_800_53", "iso_27001", "soc2", "hipaa", "fedramp",
    "pci_dss", "cmmc_l2", "gdpr", "iso_27701", "iso_42001",
    "ucf", "nist_csf", "eu_ai_act", "sec_cyber",
]
STATUSES = ["compliant", "non_compliant", "partial", "not_assessed", "not_applicable"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SCALE = 10  # 10x demo numbers


@pytest.fixture(scope="module")
def lake_parquet(tmp_path_factory):
    """Generate Parquet files at 10x demo scale."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    import random

    random.seed(42)
    base = tmp_path_factory.mktemp("lake")
    now = datetime.now(timezone.utc)

    # Control results: ~29K per run * 10 = 290K rows
    n_results = 29_000 * SCALE
    results_data = {
        "id": [str(uuid.uuid4()) for _ in range(n_results)],
        "finding_id": [str(uuid.uuid4()) for _ in range(n_results)],
        "framework": [random.choice(FRAMEWORKS) for _ in range(n_results)],
        "control_id": [f"CTRL-{random.randint(1, 200)}" for _ in range(n_results)],
        "status": [random.choice(STATUSES) for _ in range(n_results)],
        "severity": [random.choice(SEVERITIES) for _ in range(n_results)],
        "assessed_at": [
            now - timedelta(days=random.randint(0, 180)) for _ in range(n_results)
        ],
        "assessor": [
            random.choice(["assertion:mfa_check", "opa:nist_800_53", "ai:gemini", "manual"])
            for _ in range(n_results)
        ],
    }
    pq.write_table(
        pa.table(results_data),
        str(base / "control_results.parquet"),
    )

    # Posture snapshots: ~8K per day * 180 days = ~1.4M rows
    n_snapshots = 8_000 * 180
    snapshots_data = {
        "id": [str(uuid.uuid4()) for _ in range(n_snapshots)],
        "framework": [random.choice(FRAMEWORKS) for _ in range(n_snapshots)],
        "control_id": [f"CTRL-{random.randint(1, 200)}" for _ in range(n_snapshots)],
        "snapshot_date": [
            (now - timedelta(days=random.randint(0, 180))).date() for _ in range(n_snapshots)
        ],
        "posture_score": [random.uniform(0, 100) for _ in range(n_snapshots)],
        "status": [random.choice(STATUSES) for _ in range(n_snapshots)],
    }
    pq.write_table(
        pa.table(snapshots_data),
        str(base / "posture_snapshots.parquet"),
    )

    # Findings: ~550 per run * 10 = 5,500 rows
    n_findings = 550 * SCALE
    findings_data = {
        "id": [str(uuid.uuid4()) for _ in range(n_findings)],
        "severity": [random.choice(SEVERITIES) for _ in range(n_findings)],
        "source": [random.choice(["aws", "okta", "crowdstrike", "tenable"]) for _ in range(n_findings)],
        "observed_at": [
            now - timedelta(days=random.randint(0, 90)) for _ in range(n_findings)
        ],
    }
    pq.write_table(
        pa.table(findings_data),
        str(base / "findings.parquet"),
    )

    return base


class TestDuckDBFeasibility:
    """Each query must complete in < 500ms at 10x demo scale."""

    MAX_MS = 500

    def test_query_1_dashboard_framework_status_groupby(self, lake_parquet):
        """Dashboard summary: GROUP BY framework, status with counts."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "control_results.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            SELECT framework, status, COUNT(*) as cnt
            FROM read_parquet('{path}')
            GROUP BY framework, status
            ORDER BY framework, cnt DESC
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) > 0
        assert elapsed_ms < self.MAX_MS, f"Dashboard query took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Dashboard GROUP BY: {elapsed_ms:.1f}ms ({len(result)} rows)")

    def test_query_2_posture_trend_avg_by_framework(self, lake_parquet):
        """Posture trend: AVG score per framework per snapshot date."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "posture_snapshots.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            SELECT framework, snapshot_date, AVG(posture_score) as avg_score
            FROM read_parquet('{path}')
            GROUP BY framework, snapshot_date
            ORDER BY framework, snapshot_date
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) > 0
        assert elapsed_ms < self.MAX_MS, f"Posture trend query took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Posture trend AVG: {elapsed_ms:.1f}ms ({len(result)} rows)")

    def test_query_3_coverage_summary_with_counts(self, lake_parquet):
        """Coverage summary: count by framework + status with percentage."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "control_results.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            WITH totals AS (
                SELECT framework, COUNT(*) as total
                FROM read_parquet('{path}')
                GROUP BY framework
            ),
            statuses AS (
                SELECT framework, status, COUNT(*) as cnt
                FROM read_parquet('{path}')
                GROUP BY framework, status
            )
            SELECT s.framework, s.status, s.cnt,
                   ROUND(s.cnt * 100.0 / t.total, 1) as pct
            FROM statuses s
            JOIN totals t ON s.framework = t.framework
            ORDER BY s.framework, s.cnt DESC
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) > 0
        assert elapsed_ms < self.MAX_MS, f"Coverage summary took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Coverage CTE: {elapsed_ms:.1f}ms ({len(result)} rows)")

    def test_query_4_findings_with_window_pagination(self, lake_parquet):
        """Paginated findings with total count via window function."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "findings.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            SELECT *, COUNT(*) OVER() as total
            FROM read_parquet('{path}')
            WHERE severity IN ('critical', 'high')
            ORDER BY observed_at DESC
            LIMIT 100 OFFSET 0
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(result) <= 100
        assert "total" in result[0]
        assert elapsed_ms < self.MAX_MS, f"Windowed pagination took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Window pagination: {elapsed_ms:.1f}ms ({len(result)} rows, total={result[0]['total']})")

    def test_query_5_cross_framework_drift_detection(self, lake_parquet):
        """Drift detection: compare latest two snapshot dates per framework."""
        from warlock.lake.query import LakeQueryEngine
        engine = LakeQueryEngine(str(lake_parquet))
        path = str(lake_parquet / "posture_snapshots.parquet")

        start = time.perf_counter()
        result = engine.query(f"""
            WITH ranked AS (
                SELECT framework, control_id, status, posture_score, snapshot_date,
                       ROW_NUMBER() OVER (PARTITION BY framework, control_id ORDER BY snapshot_date DESC) as rn
                FROM read_parquet('{path}')
            ),
            current AS (SELECT * FROM ranked WHERE rn = 1),
            previous AS (SELECT * FROM ranked WHERE rn = 2)
            SELECT c.framework, c.control_id,
                   p.status as prev_status, c.status as curr_status,
                   p.posture_score as prev_score, c.posture_score as curr_score
            FROM current c
            JOIN previous p ON c.framework = p.framework AND c.control_id = p.control_id
            WHERE c.status != p.status
            ORDER BY c.framework, c.control_id
        """)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < self.MAX_MS, f"Drift detection took {elapsed_ms:.0f}ms (limit {self.MAX_MS}ms)"
        print(f"\n  Drift detection: {elapsed_ms:.1f}ms ({len(result)} drifted controls)")
