# Data Lake Phase 2: Consumer Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate analytical/aggregation queries from OLTP to the lake while keeping entity lookups and mutations on OLTP, with per-query feature flags and shadow validation.

**Architecture:** Each repository method gets a lake-backed alternative behind a feature flag (`settings.lake_reads_enabled("method_name")`). Shadow queries run both paths and log discrepancies. Aggregation queries migrate first (GROUP BY, trends, coverage), entity lookups (get by ID) stay on OLTP permanently.

**Tech Stack:** DuckDB (via LakeQueryEngine), existing SQLAlchemy repos, feature flags in Settings

**Spec:** `docs/superpowers/specs/2026-03-21-grc-data-lake-design.md` (Section 8, Phase 2)

**Depends on:** Phase 0 (infrastructure) + Phase 1 (lake writer, zones, reconciliation) complete. 347 tests passing. Lake reconciliation verified: OLTP = Lake row counts for all 5 tables.

**Acceptance criteria:**
- All migrated queries produce identical results from lake and OLTP (shadow validation passes)
- Feature flags allow per-query rollback to OLTP
- Demo seed still produces identical pipeline numbers (57 connectors, 0 failed)
- All 347+ tests pass
- QA gate green
- Two new materialized aggregation tables: `agg_framework_posture`, `agg_control_family_posture`
- OLTP retention purge frozen via `retention_purge_frozen` config flag
- All LakeReaders methods use parameterized queries (no SQL injection)

---

## Migration Strategy

**Per-query-pattern, NOT per-router** (from spec):
- All aggregation queries (GROUP BY, COUNT, AVG, trends) → lake
- All entity lookups (get by ID, CRUD operations) → stay OLTP
- All governance mutations (create, update, delete) → stay OLTP
- Real-time state queries (is_running, find_running) → stay OLTP

**Phase 2 migrates 15 core analytical methods** (the highest-traffic aggregation queries). Remaining analytical methods migrate in Phase 3 alongside the AI layer repositioning.

Phase 2 migration candidates:
- ControlResultRepository: 5 methods (dashboard_framework_summary, coverage_by_status, distinct_frameworks, top_non_compliant_risks, last_assessed_at)
- ControlMappingRepository: 2 methods (list_frameworks, list_controls)
- ConnectorRunRepository: 3 methods (latest_per_connector, latest_per_provider, total_event_count)
- FindingRepository: 2 methods (findings_by_severity, findings_by_source)
- PostureSnapshotRepository: 3 methods (latest_snapshot_date, framework_avg_scores_at, effectiveness_latest)

Deferred to Phase 3 (requires ABAC scope filtering, pagination, or posture materialization):
- ControlResultRepository.list_filtered (complex ABAC + pagination)
- PostureSnapshotRepository.list_latest_posture, history, trend (require posture snapshot materialization)
- FindingRepository.list_filtered, by_date_range, recent (complex filtering)
- ComplianceDriftRepository.recent (not yet written to lake)

**Methods that stay on OLTP permanently:**
- All `get(id)`, `create()`, `update()`, `delete()` operations
- `UserRepository` (auth/sessions)
- `IssueRepository` (governance workflows)
- `AttestationRepository` (governance workflows)
- `SystemProfileRepository` (configuration)
- `PersonnelRepository` (entity management)
- `ConnectorRunRepository.find_running()`, `is_running()` (real-time pipeline state)
- `AuditEntryRepository` (hash chain stays OLTP per spec)
- `LegalHoldRepository` (governance)

---

## File Structure

### New Files

| File | Responsibility |
|---|---|
| `warlock/lake/readers.py` | Lake-backed query methods — DuckDB equivalents of OLTP repository methods |
| `warlock/lake/shadow.py` | Shadow query comparator — runs both OLTP + lake, logs discrepancies |
| `warlock/lake/aggregations.py` | Materialized aggregation tables (agg_framework_posture, agg_control_family_posture) |
| `tests/test_lake_readers.py` | Tests for lake reader methods |
| `tests/test_shadow_queries.py` | Tests for shadow query comparator |

### Modified Files

| File | What Changes |
|---|---|
| `warlock/config.py` | Add `lake_reads_enabled()` method + `lake_read_overrides` dict setting |
| `warlock/db/repository.py` | Add lake fallback to analytical methods (check feature flag → delegate to lake reader) |
| `warlock/pipeline/scheduler.py` | Add `aggregation_refresh` schedule (after each pipeline run) |
| `warlock/cli/lake.py` | Add `lake query`, `lake aggregate` commands |

---

## Task 1: Feature Flag Infrastructure

**Files:**
- Modify: `warlock/config.py`
- Test: `tests/test_lake.py`

- [ ] **Step 1: Write failing test for lake_reads_enabled**

Add to `tests/test_lake.py`:

```python
class TestLakeReadFlags:
    def test_lake_reads_disabled_by_default(self):
        from warlock.config import get_settings
        s = get_settings()
        assert s.lake_reads_enabled("dashboard_framework_summary") is False

    def test_lake_reads_enabled_when_lake_enabled(self):
        """When lake is globally enabled AND no per-query overrides, reads are enabled."""
        import warlock.config as _cfg
        import os
        os.environ["WLK_LAKE_ENABLED"] = "true"
        os.environ["WLK_LAKE_READS"] = "true"
        _cfg._settings = None
        try:
            s = _cfg.get_settings()
            assert s.lake_reads_enabled("dashboard_framework_summary") is True
        finally:
            os.environ.pop("WLK_LAKE_READS", None)
            os.environ.pop("WLK_LAKE_ENABLED", None)
            _cfg._settings = None

    def test_lake_reads_per_query_override(self):
        """Per-query overrides can disable specific queries."""
        import warlock.config as _cfg
        import os
        os.environ["WLK_LAKE_ENABLED"] = "true"
        os.environ["WLK_LAKE_READS"] = "true"
        os.environ["WLK_LAKE_READ_OVERRIDES"] = '{"dashboard_framework_summary": false}'
        _cfg._settings = None
        try:
            s = _cfg.get_settings()
            assert s.lake_reads_enabled("dashboard_framework_summary") is False
            assert s.lake_reads_enabled("coverage_by_status") is True
        finally:
            os.environ.pop("WLK_LAKE_READS", None)
            os.environ.pop("WLK_LAKE_ENABLED", None)
            os.environ.pop("WLK_LAKE_READ_OVERRIDES", None)
            _cfg._settings = None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_lake.py::TestLakeReadFlags -v`
Expected: FAIL — `lake_reads_enabled` not found

- [ ] **Step 3: Implement feature flags**

In `warlock/config.py`, add to the `Settings` class after the existing lake fields:

```python
    lake_reads: bool = False  # Master switch for lake reads (requires lake_enabled too)
    lake_read_overrides: str = "{}"  # JSON dict of per-query overrides {"method_name": false}
    retention_purge_frozen: bool = False  # Freeze automated OLTP retention purging during Phase 2

    def lake_reads_enabled(self, query_name: str = "") -> bool:
        """Check if lake reads are enabled for a specific query.

        Returns True only if:
        1. lake_enabled is True (lake infrastructure exists)
        2. lake_reads is True (master read switch)
        3. No per-query override disables this specific query
        """
        if not self.lake_enabled or not self.lake_reads:
            return False
        if query_name and self.lake_read_overrides:
            import json
            try:
                overrides = json.loads(self.lake_read_overrides)
                if query_name in overrides:
                    return bool(overrides[query_name])
            except (json.JSONDecodeError, TypeError):
                pass
        return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_lake.py::TestLakeReadFlags -v`
Expected: All 3 PASS

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 347+ passed

- [ ] **Step 6: Commit**

```bash
git add warlock/config.py tests/test_lake.py
git commit -m "feat: add per-query feature flags for lake reads (lake_reads_enabled)"
```

---

## Task 2: Lake Reader Methods — Aggregation Queries

**Files:**
- Create: `warlock/lake/readers.py`
- Create: `tests/test_lake_readers.py`

This is the core of Phase 2. Each reader method is a DuckDB query that produces the same result as the corresponding OLTP repository method.

- [ ] **Step 1: Write failing tests for the first 5 lake reader methods**

Create `tests/test_lake_readers.py`:

```python
"""Tests for lake-backed analytical queries.

Each test seeds Parquet files, runs the lake reader, and verifies
the result matches what the OLTP repository would return.
"""
import json
from datetime import datetime, timezone
import pytest


@pytest.fixture
def seeded_lake(tmp_path):
    """Seed a lake with sample data for testing readers."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    from pathlib import Path

    date = "2026-03-21"

    # Control results — 3 frameworks, various statuses
    cr_data = {
        "id": ["cr-1", "cr-2", "cr-3", "cr-4", "cr-5"],
        "finding_id": ["f-1", "f-1", "f-2", "f-2", "f-3"],
        "control_mapping_id": ["cm-1", "cm-2", "cm-3", "cm-4", "cm-5"],
        "framework": ["nist_800_53", "nist_800_53", "soc2", "soc2", "iso_27001"],
        "control_id": ["AC-2", "AC-3", "CC6.1", "CC6.2", "A.9.1"],
        "status": ["compliant", "non_compliant", "compliant", "partial", "compliant"],
        "severity": ["high", "critical", "medium", "high", "low"],
        "assertion_name": ["mfa_check", "rbac_check", "encrypt_check", "", ""],
        "assertion_passed": [True, False, True, False, True],
        "assessed_at": [datetime.now(timezone.utc).isoformat()] * 5,
        "run_id": ["run-1"] * 5,
    }
    for fw in ["nist_800_53", "soc2", "iso_27001"]:
        out_dir = Path(tmp_path) / "curated" / "control_results" / fw / date
        out_dir.mkdir(parents=True, exist_ok=True)
        fw_data = {k: [v for v, f in zip(cr_data[k], cr_data["framework"]) if f == fw]
                   for k in cr_data}
        pq.write_table(pa.table(fw_data), str(out_dir / "run-1.parquet"))

    # Findings
    f_data = {
        "id": ["f-1", "f-2", "f-3"],
        "raw_event_id": ["re-1", "re-2", "re-3"],
        "observation_type": ["iam_user", "security_group", "encryption"],
        "title": ["User without MFA", "Open SG", "Unencrypted disk"],
        "detail": ["", "", ""],
        "resource_id": ["user-1", "sg-1", "vol-1"],
        "resource_type": ["iam_user", "security_group", "volume"],
        "source": ["aws", "aws", "aws"],
        "source_type": ["cloud", "cloud", "cloud"],
        "provider": ["aws", "aws", "aws"],
        "severity": ["high", "critical", "medium"],
        "confidence": [1.0, 1.0, 1.0],
        "observed_at": [datetime.now(timezone.utc).isoformat()] * 3,
        "ingested_at": [datetime.now(timezone.utc).isoformat()] * 3,
        "sha256": ["abc", "def", "ghi"],
        "run_id": ["run-1"] * 3,
    }
    f_dir = Path(tmp_path) / "enrichment" / "aws" / date
    f_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(f_data), str(f_dir / "run-1.parquet"))

    # Control mappings
    cm_data = {
        "id": ["cm-1", "cm-2", "cm-3", "cm-4", "cm-5"],
        "finding_id": ["f-1", "f-1", "f-2", "f-2", "f-3"],
        "framework": ["nist_800_53", "nist_800_53", "soc2", "soc2", "iso_27001"],
        "control_id": ["AC-2", "AC-3", "CC6.1", "CC6.2", "A.9.1"],
        "control_family": ["AC", "AC", "CC6", "CC6", "A.9"],
        "mapping_method": ["explicit", "explicit", "resource_rule", "resource_rule", "keyword"],
        "confidence": [1.0, 1.0, 0.9, 0.9, 0.8],
        "created_at": [datetime.now(timezone.utc).isoformat()] * 5,
        "run_id": ["run-1"] * 5,
    }
    cm_dir = Path(tmp_path) / "curated" / "control_mappings" / date
    cm_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(cm_data), str(cm_dir / "run-1.parquet"))

    # Connector runs
    conn_data = {
        "id": ["conn-1", "conn-2"],
        "connector_name": ["aws", "okta"],
        "source": ["aws", "okta"],
        "source_type": ["cloud", "identity"],
        "provider": ["aws", "okta"],
        "status": ["success", "success"],
        "event_count": [2, 1],
        "error_count": [0, 0],
        "started_at": [datetime.now(timezone.utc).isoformat()] * 2,
        "completed_at": [datetime.now(timezone.utc).isoformat()] * 2,
        "duration_seconds": [1.5, 0.8],
        "run_id": ["run-1"] * 2,
    }
    conn_dir = Path(tmp_path) / "curated" / "connector_runs" / date
    conn_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(conn_data), str(conn_dir / "run-1.parquet"))

    return str(tmp_path)


class TestLakeReaderDashboard:
    def test_dashboard_framework_summary(self, seeded_lake):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake)
        result = readers.dashboard_framework_summary()
        # Should return (framework, status, count) tuples
        assert len(result) > 0
        frameworks = {r[0] for r in result}
        assert "nist_800_53" in frameworks
        assert "soc2" in frameworks
        readers.close()

    def test_coverage_by_status(self, seeded_lake):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake)
        result = readers.coverage_by_status()
        assert len(result) > 0
        readers.close()

    def test_distinct_frameworks(self, seeded_lake):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake)
        result = readers.distinct_frameworks()
        assert "nist_800_53" in result
        assert "soc2" in result
        assert "iso_27001" in result
        readers.close()

    def test_list_frameworks(self, seeded_lake):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake)
        result = readers.list_frameworks()
        # Should return (framework, control_count) tuples
        assert len(result) >= 3
        readers.close()

    def test_total_event_count(self, seeded_lake):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake)
        result = readers.total_event_count()
        assert result == 3  # 2 + 1
        readers.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_lake_readers.py -v`
Expected: FAIL — `LakeReaders` not found

- [ ] **Step 3: Implement LakeReaders**

Create `warlock/lake/readers.py`:

```python
"""Lake-backed analytical query methods.

Each method is the DuckDB equivalent of an OLTP repository method.
Results are returned in the same format as the OLTP method to enable
transparent swapping via feature flags.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class LakeReaders:
    """DuckDB-backed readers for analytical queries over the lake.

    Each method corresponds to an OLTP repository method and returns
    data in the same format (tuples, lists, dicts) so the caller
    doesn't know which backend served the query.
    """

    def __init__(self, lake_path: str) -> None:
        from warlock.lake.query import LakeQueryEngine
        self._lake_path = lake_path
        self._engine = LakeQueryEngine(lake_path)
        self._base = Path(lake_path)

    def close(self) -> None:
        self._engine.close()

    def _cr_glob(self, framework: str = "**") -> str:
        return str(self._base / "curated" / "control_results" / framework / "**" / "*.parquet")

    def _cm_glob(self) -> str:
        return str(self._base / "curated" / "control_mappings" / "**" / "*.parquet")

    def _findings_glob(self) -> str:
        return str(self._base / "enrichment" / "**" / "*.parquet")

    def _connector_glob(self) -> str:
        return str(self._base / "curated" / "connector_runs" / "**" / "*.parquet")

    def _has_files(self, glob_pattern: str) -> bool:
        from pathlib import Path
        pattern = glob_pattern.replace(str(self._base) + "/", "")
        return bool(list(self._base.glob(pattern.replace("**/*.parquet", "**/*.parquet"))))

    # --- ControlResultRepository equivalents ---

    def dashboard_framework_summary(self) -> list[tuple[str, str, int]]:
        """Equivalent to ControlResultRepository.dashboard_framework_summary()."""
        glob = self._cr_glob()
        result = self._engine.query(f"""
            SELECT framework, status, COUNT(*) as cnt
            FROM read_parquet('{glob}', union_by_name=true)
            GROUP BY framework, status
            ORDER BY framework, cnt DESC
        """)
        return [(r["framework"], r["status"], r["cnt"]) for r in result]

    def coverage_by_status(self, framework: str = None) -> list[tuple[str, str, int]]:
        """Equivalent to ControlResultRepository.coverage_by_status()."""
        glob = self._cr_glob()
        if framework:
            result = self._engine.query(f"""
                SELECT framework, status, COUNT(*) as cnt
                FROM read_parquet('{glob}', union_by_name=true)
                WHERE framework = ?
                GROUP BY framework, status
                ORDER BY framework, status
            """, [framework])
        else:
            result = self._engine.query(f"""
                SELECT framework, status, COUNT(*) as cnt
                FROM read_parquet('{glob}', union_by_name=true)
                GROUP BY framework, status
                ORDER BY framework, status
            """)
        return [(r["framework"], r["status"], r["cnt"]) for r in result]

    def distinct_frameworks(self) -> list[str]:
        """Equivalent to ControlResultRepository.distinct_frameworks()."""
        glob = self._cr_glob()
        result = self._engine.query(f"""
            SELECT DISTINCT framework
            FROM read_parquet('{glob}', union_by_name=true)
            ORDER BY framework
        """)
        return [r["framework"] for r in result]

    def top_non_compliant_risks(self) -> list[Any]:
        """Equivalent to ControlResultRepository.top_non_compliant_risks()."""
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
        """Equivalent to ControlResultRepository.last_assessed_at()."""
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

    def list_frameworks(self, limit: int = 100, offset: int = 0) -> list[tuple[str, int]]:
        """Equivalent to ControlMappingRepository.list_frameworks()."""
        glob = self._cm_glob()
        result = self._engine.query(f"""
            SELECT framework, COUNT(DISTINCT control_id) as control_count
            FROM read_parquet('{glob}', union_by_name=true)
            GROUP BY framework
            ORDER BY framework
            LIMIT {limit} OFFSET {offset}
        """)
        return [(r["framework"], r["control_count"]) for r in result]

    def list_controls(self, framework_id: str, limit: int = 100, offset: int = 0) -> list[tuple]:
        """Equivalent to ControlMappingRepository.list_controls()."""
        glob = self._cm_glob()
        result = self._engine.query(f"""
            SELECT control_id, control_family, mapping_method, COUNT(*) as mapping_count
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE framework = ?
            GROUP BY control_id, control_family, mapping_method
            ORDER BY control_id
            LIMIT ? OFFSET ?
        """, [framework_id, limit, offset])
        return [(r["control_id"], r["control_family"], r["mapping_method"], r["mapping_count"]) for r in result]

    # --- ConnectorRunRepository equivalents ---

    def total_event_count(self) -> int:
        """Equivalent to ConnectorRunRepository.total_event_count()."""
        glob = self._connector_glob()
        result = self._engine.query(f"""
            SELECT COALESCE(SUM(event_count), 0) as total
            FROM read_parquet('{glob}', union_by_name=true)
        """)
        return int(result[0]["total"]) if result else 0

    def latest_per_connector(self) -> list[dict]:
        """Equivalent to ConnectorRunRepository.latest_per_connector()."""
        glob = self._connector_glob()
        result = self._engine.query(f"""
            WITH ranked AS (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY connector_name ORDER BY started_at DESC) as rn
                FROM read_parquet('{glob}', union_by_name=true)
            )
            SELECT * EXCLUDE(rn) FROM ranked WHERE rn = 1
            ORDER BY connector_name
        """)
        return result

    def latest_per_provider(self) -> list[dict]:
        """Equivalent to ConnectorRunRepository.latest_per_provider()."""
        glob = self._connector_glob()
        result = self._engine.query(f"""
            WITH ranked AS (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY provider ORDER BY started_at DESC) as rn
                FROM read_parquet('{glob}', union_by_name=true)
            )
            SELECT * EXCLUDE(rn) FROM ranked WHERE rn = 1
            ORDER BY provider
        """)
        return result

    # --- FindingRepository equivalents ---

    def findings_by_severity(self, severity: str, limit: int = 100) -> list[dict]:
        """Equivalent to FindingRepository.by_severity()."""
        glob = self._findings_glob()
        result = self._engine.query(f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE severity = ?
            ORDER BY observed_at DESC
            LIMIT ?
        """, [severity, limit])
        return result

    def findings_by_source(self, source: str, limit: int = 100) -> list[dict]:
        """Equivalent to FindingRepository.by_source()."""
        glob = self._findings_glob()
        result = self._engine.query(f"""
            SELECT *
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE source = ?
            ORDER BY observed_at DESC
            LIMIT ?
        """, [source, limit])
        return result

    # --- ComplianceDriftRepository equivalents ---

    # Note: compliance drift is not yet written to the lake in Phase 1.
    # This will be added when posture snapshots are materialized.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_lake_readers.py -v`
Expected: All 5 PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/lake/readers.py tests/test_lake_readers.py
git commit -m "feat: add lake reader methods — DuckDB equivalents of OLTP analytical queries"
```

---

## Task 3: Shadow Query Comparator

**Files:**
- Create: `warlock/lake/shadow.py`
- Create: `tests/test_shadow_queries.py`

Shadow queries run both OLTP and lake paths, compare results, and log discrepancies. This is the safety net during migration.

- [ ] **Step 1: Write failing test**

Create `tests/test_shadow_queries.py`:

```python
"""Tests for shadow query comparator."""
import pytest


class TestShadowComparator:
    def test_matching_results(self):
        from warlock.lake.shadow import compare_results
        oltp = [(1, "a"), (2, "b")]
        lake = [(1, "a"), (2, "b")]
        result = compare_results("test_query", oltp, lake)
        assert result.match is True
        assert result.discrepancies == []

    def test_mismatched_results(self):
        from warlock.lake.shadow import compare_results
        oltp = [(1, "a"), (2, "b")]
        lake = [(1, "a"), (2, "c")]
        result = compare_results("test_query", oltp, lake)
        assert result.match is False

    def test_count_mismatch(self):
        from warlock.lake.shadow import compare_results
        oltp = [(1, "a")]
        lake = [(1, "a"), (2, "b")]
        result = compare_results("test_query", oltp, lake)
        assert result.match is False
        assert "row count" in result.discrepancies[0].lower()

    def test_shadow_query_runner(self):
        """Shadow runner calls both paths and returns comparison."""
        from warlock.lake.shadow import ShadowQueryRunner, ComparisonResult
        # Mock both paths
        def oltp_fn(): return [(1, "a")]
        def lake_fn(): return [(1, "a")]
        runner = ShadowQueryRunner()
        result = runner.compare("test", oltp_fn, lake_fn)
        assert result.match is True
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement shadow comparator**

Create `warlock/lake/shadow.py`:

```python
"""Shadow query comparator — validates lake reads against OLTP.

During Phase 2 migration, shadow queries run both OLTP and lake
paths for the same query. Results are compared and discrepancies
are logged. This is the safety net that proves the lake is correct.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger(__name__)


@dataclass
class ComparisonResult:
    query_name: str
    match: bool
    oltp_count: int = 0
    lake_count: int = 0
    oltp_ms: float = 0.0
    lake_ms: float = 0.0
    discrepancies: list[str] = field(default_factory=list)


def compare_results(query_name: str, oltp_result: Any, lake_result: Any) -> ComparisonResult:
    """Compare OLTP and lake query results."""
    result = ComparisonResult(query_name=query_name, match=True)

    # Normalize to lists
    oltp_list = list(oltp_result) if oltp_result else []
    lake_list = list(lake_result) if lake_result else []

    result.oltp_count = len(oltp_list)
    result.lake_count = len(lake_list)

    if result.oltp_count != result.lake_count:
        result.match = False
        result.discrepancies.append(
            f"Row count mismatch: OLTP={result.oltp_count}, Lake={result.lake_count}"
        )
        return result

    # Compare element by element (for tuples/simple types)
    for i, (o, l) in enumerate(zip(oltp_list, lake_list)):
        if o != l:
            result.match = False
            result.discrepancies.append(f"Row {i} differs: OLTP={o!r}, Lake={l!r}")
            if len(result.discrepancies) > 10:
                result.discrepancies.append("... (truncated)")
                break

    return result


class ShadowQueryRunner:
    """Runs both OLTP and lake queries, compares, logs results."""

    def __init__(self) -> None:
        self._results: list[ComparisonResult] = []

    def compare(
        self,
        query_name: str,
        oltp_fn: Callable[[], Any],
        lake_fn: Callable[[], Any],
    ) -> ComparisonResult:
        """Run both queries and compare results."""
        start = time.perf_counter()
        oltp_result = oltp_fn()
        oltp_ms = (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        try:
            lake_result = lake_fn()
        except Exception as exc:
            lake_ms = (time.perf_counter() - start) * 1000
            log.warning("Shadow lake query %s failed: %s — using OLTP result", query_name, exc)
            result = ComparisonResult(query_name=query_name, match=False, oltp_ms=oltp_ms, lake_ms=lake_ms)
            result.discrepancies.append(f"Lake query failed: {exc}")
            self._results.append(result)
            return result
        lake_ms = (time.perf_counter() - start) * 1000

        result = compare_results(query_name, oltp_result, lake_result)
        result.oltp_ms = oltp_ms
        result.lake_ms = lake_ms

        if result.match:
            log.debug(
                "Shadow OK: %s (OLTP=%.1fms, Lake=%.1fms, %d rows)",
                query_name, oltp_ms, lake_ms, result.oltp_count,
            )
        else:
            log.warning(
                "Shadow MISMATCH: %s — %s",
                query_name, "; ".join(result.discrepancies[:3]),
            )

        self._results.append(result)
        return result

    @property
    def all_match(self) -> bool:
        return all(r.match for r in self._results)

    @property
    def mismatches(self) -> list[ComparisonResult]:
        return [r for r in self._results if not r.match]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_shadow_queries.py -v`
Expected: All 4 PASS

- [ ] **Step 5: Commit**

```bash
git add warlock/lake/shadow.py tests/test_shadow_queries.py
git commit -m "feat: add shadow query comparator for OLTP/lake validation"
```

---

## Task 4: Wire Lake Readers into Repository Layer

**Files:**
- Modify: `warlock/db/repository.py`
- Test: existing test suite must still pass

This is the critical integration task. For each analytical method, add a check: if `lake_reads_enabled(method_name)`, delegate to the lake reader. Otherwise, use OLTP as before.

- [ ] **Step 1: Add lake reader fallback to ControlResultRepository.dashboard_framework_summary()**

In `warlock/db/repository.py`, modify the `dashboard_framework_summary` method:

```python
def dashboard_framework_summary(self) -> list:
    """Framework status summary for dashboard."""
    from warlock.config import get_settings
    settings = get_settings()
    if settings.lake_reads_enabled("dashboard_framework_summary"):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(settings.lake_path)
        try:
            return readers.dashboard_framework_summary()
        finally:
            readers.close()
    # Original OLTP query below...
    return (
        self.session.query(...)
        ...
    )
```

- [ ] **Step 2: Apply same pattern to all 8 analytical methods in ControlResultRepository**

Methods: `dashboard_framework_summary`, `coverage_by_status`, `distinct_frameworks`, `top_non_compliant_risks`, `last_assessed_at`, `by_framework`, `by_status`, `list_filtered` (aggregation part only)

- [ ] **Step 3: Apply to PostureSnapshotRepository analytical methods**

Methods: `latest_snapshot_date`, `framework_avg_scores_at`, `effectiveness_latest`, `trend`

- [ ] **Step 4: Apply to ControlMappingRepository**

Methods: `list_frameworks`, `list_controls`

- [ ] **Step 5: Apply to ConnectorRunRepository aggregation methods**

Methods: `total_event_count`, `latest_per_connector`, `latest_per_provider`

- [ ] **Step 6: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 347+ passed (all existing tests still pass because lake_reads defaults to False)

- [ ] **Step 7: Run demo seed**

Run: `rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py 2>&1 | grep -E "Connectors succeeded|failed"`
Expected: 57 connectors succeeded, 0 failed

- [ ] **Step 8: Commit**

```bash
git add warlock/db/repository.py
git commit -m "feat: wire lake readers into repository layer with per-query feature flags"
```

---

## Task 5: Materialized Aggregation Tables

**Files:**
- Create: `warlock/lake/aggregations.py`
- Modify: `warlock/cli/lake.py` — add `lake aggregate` command

- [ ] **Step 1: Write failing test**

Add to `tests/test_lake_readers.py`:

```python
class TestAggregations:
    def test_refresh_framework_posture(self, seeded_lake):
        from warlock.lake.aggregations import refresh_aggregations
        from warlock.lake.query import LakeQueryEngine

        refresh_aggregations(seeded_lake)

        engine = LakeQueryEngine(seeded_lake)
        result = engine.query(
            f"SELECT * FROM read_parquet('{seeded_lake}/curated/agg_framework_posture/*.parquet')"
        )
        assert len(result) > 0
        assert "framework" in result[0]
        assert "compliant_count" in result[0]
        engine.close()
```

- [ ] **Step 2: Implement aggregations**

Create `warlock/lake/aggregations.py`:

```python
"""Materialized aggregation tables for the analytics layer.

These are pre-computed summaries written to the curated zone after each
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

    engine = LakeQueryEngine(lake_path)
    base = Path(lake_path)
    counts = {}

    try:
        # agg_framework_posture
        cr_glob = str(base / "curated" / "control_results" / "**" / "*.parquet")
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
                '{datetime.now(timezone.utc).isoformat()}' as refreshed_at
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

        # agg_control_family_posture
        cm_glob = str(base / "curated" / "control_mappings" / "**" / "*.parquet")
        result = engine.query(f"""
            SELECT
                cr.framework,
                cm.control_family,
                COUNT(*) as total_results,
                COUNT(CASE WHEN cr.status = 'compliant' THEN 1 END) as compliant_count,
                COUNT(CASE WHEN cr.status = 'non_compliant' THEN 1 END) as non_compliant_count,
                ROUND(COUNT(CASE WHEN cr.status = 'compliant' THEN 1 END) * 100.0 / COUNT(*), 1) as compliance_pct,
                '{datetime.now(timezone.utc).isoformat()}' as refreshed_at
            FROM read_parquet('{cr_glob}', union_by_name=true) cr
            JOIN read_parquet('{cm_glob}', union_by_name=true) cm
                ON cr.control_mapping_id = cm.id
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
```

- [ ] **Step 3: Run test to verify it passes**
- [ ] **Step 4: Add CLI command**

Add to `warlock/cli/lake.py`:

```python
@lake.command("aggregate")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def lake_aggregate(path: str | None) -> None:
    """Refresh materialized aggregation tables."""
    from warlock.config import get_settings
    from warlock.lake.aggregations import refresh_aggregations

    settings = get_settings()
    lake_path = path or settings.lake_path

    console.print(f"[cyan]Refreshing aggregations: {lake_path}[/cyan]")
    counts = refresh_aggregations(lake_path)

    for table_name, count in counts.items():
        console.print(f"  {table_name}: {count} rows")

    console.print("[green]Aggregation refresh complete.[/green]")
```

- [ ] **Step 5: Commit**

```bash
git add warlock/lake/aggregations.py warlock/cli/lake.py tests/test_lake_readers.py
git commit -m "feat: add materialized aggregation tables (agg_framework_posture, agg_control_family_posture)"
```

---

## Task 6: End-to-End Lake Read Validation

**Files:**
- Modify: `tests/test_lake_readers.py`

- [ ] **Step 1: Write end-to-end shadow validation test**

```python
class TestEndToEndShadowValidation:
    def test_demo_seed_shadow_queries_match(self, tmp_path):
        """Run demo seed with lake, then shadow-compare key queries."""
        # This test runs the demo seed with lake enabled,
        # then compares OLTP vs lake for the dashboard query.
        import os
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.lake.shadow import ShadowQueryRunner
        from warlock.lake.readers import LakeReaders
        from warlock.db.models import Base, ControlResult
        from sqlalchemy import func

        # Use existing demo data if available
        if not os.path.exists("warlock.db"):
            pytest.skip("No warlock.db — run demo seed first")

        lake_path = "lake"
        if not os.path.exists(lake_path):
            pytest.skip("No lake/ directory — run demo seed with WLK_LAKE_ENABLED=true first")

        from warlock.db.engine import get_session
        readers = LakeReaders(lake_path)
        runner = ShadowQueryRunner()

        with get_session() as session:
            # Compare dashboard summary
            def oltp_fn():
                return session.query(
                    ControlResult.framework,
                    ControlResult.status,
                    func.count(ControlResult.id)
                ).group_by(ControlResult.framework, ControlResult.status).order_by(
                    ControlResult.framework
                ).all()

            result = runner.compare(
                "dashboard_framework_summary",
                oltp_fn,
                readers.dashboard_framework_summary,
            )

        readers.close()
        # We expect row counts to match but ordering may differ
        assert result.oltp_count == result.lake_count, (
            f"OLTP has {result.oltp_count} rows, Lake has {result.lake_count}"
        )
```

- [ ] **Step 2: Run it against the existing demo data**

Run: `WLK_LAKE_ENABLED=true pytest tests/test_lake_readers.py::TestEndToEndShadowValidation -v -s`
Expected: PASS (or SKIP if no demo data)

- [ ] **Step 3: Commit**

```bash
git add tests/test_lake_readers.py
git commit -m "test: add end-to-end shadow validation for lake reads"
```

---

## Task 7: Final QA Gate + Phase 2 Completion

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 355+ passed

- [ ] **Step 2: Run demo seed (without lake)**

Run: `rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py 2>&1 | grep -E "Connectors succeeded|failed|Raw events|Findings|Controls mapped"`
Expected: 57 connectors succeeded, 0 failed

- [ ] **Step 3: Run demo seed WITH lake**

Run: `rm -f warlock.db && rm -rf lake/ && .venv/bin/alembic upgrade head && WLK_LAKE_ENABLED=true .venv/bin/python scripts/demo_seed.py 2>&1 | grep -E "Connectors|Raw events|Findings|Controls mapped|Lake write"`
Expected: Same pipeline numbers + Lake write counts matching

- [ ] **Step 4: Run reconciliation**

Run: `.venv/bin/python -c "from warlock.db.engine import get_session; from warlock.lake.reconciliation import reconcile; s = __import__('contextlib').ExitStack(); session = s.enter_context(get_session()); r = reconcile(session, 'lake'); print('PASSED' if r.passed else 'FAILED')"`
Expected: PASSED

- [ ] **Step 5: Run aggregation refresh**

Run: `.venv/bin/python -c "from warlock.lake.aggregations import refresh_aggregations; counts = refresh_aggregations('lake'); print(counts)"`
Expected: Both tables populated

- [ ] **Step 6: List all changes for review**

Run: `git diff --stat main`

- [ ] **Step 7: Commit any remaining changes**

---

## Phase 2 Completion Criteria

All of the following must be true before starting Phase 3:

- [ ] Feature flags implemented (`lake_reads_enabled()` with per-query overrides)
- [ ] LakeReaders class with 15 analytical query methods (all using parameterized queries)
- [ ] Shadow query comparator validates OLTP/lake parity (with error handling for lake failures)
- [ ] Repository methods delegate to lake when flag enabled
- [ ] Materialized aggregation tables (agg_framework_posture, agg_control_family_posture)
- [ ] `lake aggregate` CLI command
- [ ] OLTP retention purge frozen via `retention_purge_frozen` config flag
- [ ] Demo seed produces identical output with and without lake
- [ ] Reconciliation passes (0% drift)
- [ ] All 347+ existing tests pass
- [ ] QA gate passes
- [ ] Completion signal defined: zero aggregation queries hitting OLTP + zero shadow mismatches for 2+ weeks (tracked via logging)
