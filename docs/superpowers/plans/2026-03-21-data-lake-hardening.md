# Data Lake Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 10 gaps identified by GRC Unicorn review to bring the data lake from B+ to A — typed Parquet columns, ABAC enforcement, legal hold checking, Iceberg wiring, bridge tables, SCD Type 2, hash reconciliation, RAG, and code cleanup.

**Architecture:** Tasks are ordered by dependency. Quick cleanup first (Tasks 1-3), then security (Tasks 4-5), then data model (Tasks 6-8), then infrastructure (Task 9), then AI (Task 10). **Dependencies:** Task 4 depends on Task 2 (both modify readers.py). Task 6 depends on Task 1 (both modify domains.py). Tasks 7-10 are independent of each other but should follow Task 1.

**Tech Stack:** PyArrow (typed schemas), DuckDB, PyIceberg, existing ABAC scope_filter pattern, existing LegalHold model

**Spec:** `docs/superpowers/specs/2026-03-21-grc-data-lake-design.md`

**Depends on:** All phases complete (Phases 0-3). 486 tests passing. Lake reconciliation verified.

**Acceptance criteria:**
- All Parquet columns use native types (int, float, bool, timestamp) not strings
- ABAC scope_filter applied to all lake reader methods that have OLTP equivalents with scope_filter
- Legal hold checking in maintenance expire + OLTP thinning
- SHA-256 hash sampling in reconciliation
- All 6 bridge tables implemented
- SCD Type 2 logic for entity dimension writers
- Iceberg catalog and schema wired to zone writers
- RAG indexes curated zone data
- Zero duplicate utility functions
- Posture snapshot readers query real lake data
- Demo seed unchanged (57 connectors, 0 failed)
- All 486+ tests pass

---

## File Structure

### New Files

| File | Responsibility |
|---|---|
| `warlock/lake/utils.py` | Shared utilities — `model_to_dict`, `today_partition`, `ensure_dir` |
| `warlock/lake/scd.py` | SCD Type 2 dimension management logic |
| `warlock/lake/bridges.py` | Bridge table writers (crosswalk, entity-relationship, incident) |
| `tests/test_lake_hardening.py` | Tests for ABAC, legal holds, hash sampling, typed columns, bridges, SCD |

### Modified Files

| File | What Changes |
|---|---|
| `warlock/lake/writer.py` | Import `model_to_dict` from utils instead of defining locally |
| `warlock/lake/backfill.py` | Import `model_to_dict` from utils instead of defining locally |
| `warlock/lake/zones.py` | Import `today_partition`, `ensure_dir` from utils; use typed PyArrow columns |
| `warlock/lake/domains.py` | Import from utils; use typed PyArrow columns in `_write_table()` |
| `warlock/lake/readers.py` | Add `scope_filter` parameter to applicable methods; implement posture readers |
| `warlock/lake/maintenance.py` | Add legal hold checking before `expire_snapshots()` |
| `warlock/lake/oltp_thin.py` | Add legal hold checking before `thin_oltp()` |
| `warlock/lake/reconciliation.py` | Add SHA-256 hash sampling to `reconcile()` |
| `warlock/lake/catalog.py` | Wire into zone writers via `IcebergTableManager` |
| `warlock/lake/schema.py` | Add `get_pyarrow_schema()` for typed Parquet writes |

---

## Task 1: Extract Duplicate Utilities

**Files:**
- Create: `warlock/lake/utils.py`
- Modify: `warlock/lake/writer.py` (remove `_model_to_dict`, import from utils)
- Modify: `warlock/lake/backfill.py` (remove `_model_to_dict`, import from utils)
- Modify: `warlock/lake/zones.py` (remove `_today_partition`, `_ensure_dir`, import from utils)
- Modify: `warlock/lake/domains.py` (remove `_today_partition`, `_ensure_dir`, import from utils)

- [ ] **Step 1: Create `warlock/lake/utils.py`**

```python
"""Shared utilities for lake modules.

Centralizes functions used by multiple lake modules to avoid duplication.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def model_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a SQLAlchemy model instance to a dict.

    Handles JSON fields by serializing with sort_keys=True for hash integrity.
    Uses the same serialization as OLTP to preserve SHA-256 consistency.
    """
    d: dict[str, Any] = {}
    for col in obj.__table__.columns:
        val = getattr(obj, col.name, None)
        if isinstance(val, (dict, list)):
            val = json.dumps(val, sort_keys=True, default=str)
        d[col.name] = val
    return d


def today_partition() -> str:
    """Return today's date as YYYY-MM-DD for Parquet partitioning."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def ensure_dir(path: Path) -> None:
    """Create directory and parents if they don't exist."""
    path.mkdir(parents=True, exist_ok=True)


def serialize_json_field(value: Any) -> str:
    """Serialize a JSON-capable field to a deterministic string.

    Uses sort_keys=True and default=str to preserve SHA-256 hash integrity
    across OLTP and lake representations.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, default=str)
```

- [ ] **Step 2: Update imports in writer.py, backfill.py, zones.py, domains.py**

In each file, remove the local duplicate function and replace with:
```python
from warlock.lake.utils import model_to_dict  # writer.py, backfill.py
from warlock.lake.utils import today_partition, ensure_dir  # zones.py, domains.py
from warlock.lake.utils import serialize_json_field  # zones.py
```

- [ ] **Step 3: Run full test suite to verify refactor is safe**

Run: `pytest tests/ -x -q`
Expected: 486+ passed

- [ ] **Step 4: Commit**

```bash
git add warlock/lake/utils.py warlock/lake/writer.py warlock/lake/backfill.py warlock/lake/zones.py warlock/lake/domains.py
git commit -m "refactor: extract duplicate lake utilities to warlock/lake/utils.py"
```

---

## Task 2: Implement Posture Snapshot Readers

**Files:**
- Modify: `warlock/lake/readers.py` (replace 3 stubs with real implementations)
- Test: `tests/test_lake_hardening.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_lake_hardening.py`:

```python
"""Tests for lake hardening — ABAC, legal holds, typed columns, readers, bridges."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest


@pytest.fixture
def lake_with_posture(tmp_path):
    """Seed lake with posture snapshot data."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    date = "2026-03-21"
    snapshots = {
        "id": ["ps-1", "ps-2", "ps-3"],
        "framework": ["nist_800_53", "nist_800_53", "soc2"],
        "control_id": ["AC-2", "AC-3", "CC6.1"],
        "system_profile_id": ["sys-1", "sys-1", "sys-1"],
        "snapshot_date": [date, date, date],
        "posture_score": ["85.0", "72.0", "91.0"],
        "status": ["compliant", "partial", "compliant"],
        "run_id": ["run-1", "run-1", "run-1"],
    }
    for fw in ["nist_800_53", "soc2"]:
        d = Path(tmp_path) / "curated" / "posture_snapshots" / fw / date
        d.mkdir(parents=True, exist_ok=True)
        fw_data = {k: [v for v, f in zip(snapshots[k], snapshots["framework"]) if f == fw]
                   for k in snapshots}
        pq.write_table(pa.table(fw_data), str(d / "run-1.parquet"))
    return str(tmp_path)


class TestPostureReaders:
    def test_latest_snapshot_date(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.latest_snapshot_date()
        assert result is not None
        readers.close()

    def test_framework_avg_scores(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.framework_avg_scores_at()
        assert len(result) >= 2
        readers.close()

    def test_effectiveness_latest(self, lake_with_posture):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(lake_with_posture)
        result = readers.effectiveness_latest()
        assert isinstance(result, list)
        readers.close()
```

- [ ] **Step 2: Run tests to verify they fail (stubs return None/[])**

- [ ] **Step 3: Implement real posture readers**

In `warlock/lake/readers.py`, replace the 3 stubs:

```python
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
        return datetime.fromisoformat(val) if isinstance(val, str) else val
    return None

def framework_avg_scores_at(self, snapshot_date=None) -> list[tuple[str, float]]:
    """Average posture score per framework."""
    glob = self._posture_glob()
    if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
        return []
    if snapshot_date:
        result = self._engine.query(f"""
            SELECT framework, AVG(CAST(posture_score AS DOUBLE)) as avg_score
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE snapshot_date = ?
            GROUP BY framework ORDER BY framework
        """, [str(snapshot_date)])
    else:
        result = self._engine.query(f"""
            SELECT framework, AVG(CAST(posture_score AS DOUBLE)) as avg_score
            FROM read_parquet('{glob}', union_by_name=true)
            GROUP BY framework ORDER BY framework
        """)
    return [(r["framework"], float(r["avg_score"])) for r in result]

def effectiveness_latest(self, framework: str = None, days: int = 30) -> list[dict]:
    """Control effectiveness from posture snapshots."""
    glob = self._posture_glob()
    if not list(self._base.glob("curated/posture_snapshots/**/*.parquet")):
        return []
    if framework:
        result = self._engine.query(f"""
            SELECT framework, control_id, status, CAST(posture_score AS DOUBLE) as posture_score, snapshot_date
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE framework = ?
            ORDER BY snapshot_date DESC
        """, [framework])
    else:
        result = self._engine.query(f"""
            SELECT framework, control_id, status, CAST(posture_score AS DOUBLE) as posture_score, snapshot_date
            FROM read_parquet('{glob}', union_by_name=true)
            ORDER BY snapshot_date DESC
        """)
    return result
```

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

---

## Task 3: Legal Hold Checking in Maintenance + Thinning

**Files:**
- Modify: `warlock/lake/maintenance.py`
- Modify: `warlock/lake/oltp_thin.py`
- Test: `tests/test_lake_hardening.py`

- [ ] **Step 1: Write tests**

```python
class TestLegalHoldChecking:
    def test_expire_blocked_by_legal_hold(self):
        """expire_snapshots should abort if active legal hold exists."""
        from warlock.lake.maintenance import expire_snapshots_safe
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base, LegalHold

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(LegalHold(
                id="lh-1", hold_type="litigation",
                trigger_event="Investigation",
                is_active=True,
            ))
            session.flush()
            result = expire_snapshots_safe(session, "/tmp/empty-lake")
            assert result.get("blocked_by_hold") is True

    def test_thin_blocked_by_legal_hold(self):
        """thin_oltp should abort if active legal hold exists."""
        from warlock.lake.oltp_thin import thin_oltp_safe
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from warlock.db.models import Base, LegalHold

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(LegalHold(
                id="lh-1", hold_type="litigation",
                trigger_event="Investigation",
                is_active=True,
            ))
            session.flush()
            stats = thin_oltp_safe(session, dry_run=True)
            assert stats.total_removed == 0
            assert "legal hold" in stats.errors[0].lower()
```

- [ ] **Step 2: Implement legal hold checks**

In `warlock/lake/maintenance.py`, add a safe wrapper:
```python
def expire_snapshots_safe(session, lake_path: str, **kwargs) -> dict:
    """expire_snapshots with legal hold checking."""
    from warlock.db.models import LegalHold
    active_holds = session.query(LegalHold).filter(LegalHold.is_active == True).count()
    if active_holds > 0:
        log.warning("Snapshot expiry blocked: %d active legal hold(s)", active_holds)
        return {"blocked_by_hold": True, "active_holds": active_holds}
    return expire_snapshots(lake_path, **kwargs)
```

In `warlock/lake/oltp_thin.py`, add a safe wrapper:
```python
def thin_oltp_safe(session, dry_run: bool = True) -> ThinStats:
    """thin_oltp with legal hold checking."""
    from warlock.db.models import LegalHold
    active_holds = session.query(LegalHold).filter(LegalHold.is_active == True).count()
    if active_holds > 0:
        stats = ThinStats()
        stats.errors.append(f"Blocked by {active_holds} active legal hold(s)")
        return stats
    return thin_oltp(session, dry_run=dry_run)
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Update CLI commands to use safe wrappers**
- [ ] **Step 5: Commit**

---

## Task 4: ABAC Scope Filtering in Lake Readers

**Files:**
- Modify: `warlock/lake/readers.py`
- Test: `tests/test_lake_hardening.py`

The ABAC `scope_filter` in OLTP is a callable that modifies a SQLAlchemy query. For DuckDB, we need a different approach: accept a framework filter list and apply it as a WHERE clause.

- [ ] **Step 1: Write test**

```python
class TestABACLakeReaders:
    def test_dashboard_with_framework_scope(self, seeded_lake_for_readers):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake_for_readers)
        # Scope to only soc2
        result = readers.dashboard_framework_summary(allowed_frameworks=["soc2"])
        assert all(r[0] == "soc2" for r in result)
        readers.close()

    def test_coverage_with_framework_scope(self, seeded_lake_for_readers):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake_for_readers)
        result = readers.coverage_by_status(allowed_frameworks=["nist_800_53"])
        assert all(r[0] == "nist_800_53" for r in result)
        readers.close()

    def test_no_scope_returns_all(self, seeded_lake_for_readers):
        from warlock.lake.readers import LakeReaders
        readers = LakeReaders(seeded_lake_for_readers)
        result = readers.distinct_frameworks()
        assert len(result) >= 2  # Has both nist and soc2
        readers.close()
```

Use the existing `seeded_lake` fixture from `tests/test_lake_readers.py`, or create a similar one in this test file.

- [ ] **Step 2: Add `allowed_frameworks` parameter to all analytical reader methods**

Pattern for each method:
```python
def dashboard_framework_summary(self, allowed_frameworks: list[str] | None = None, allowed_system_profiles: list[str] | None = None) -> list[tuple[str, str, int]]:
    glob = self._cr_glob()
    where = ""
    params = []
    if allowed_frameworks:
        placeholders = ", ".join("?" for _ in allowed_frameworks)
        where = f"WHERE framework IN ({placeholders})"
        params = list(allowed_frameworks)
    result = self._engine.query(f"""
        SELECT framework, status, COUNT(*) as cnt
        FROM read_parquet('{glob}', union_by_name=true)
        {where}
        GROUP BY framework, status
        ORDER BY framework, cnt DESC
    """, params or None)
    return [(r["framework"], r["status"], r["cnt"]) for r in result]
```

Apply to: `dashboard_framework_summary`, `coverage_by_status`, `distinct_frameworks`, `top_non_compliant_risks`, `last_assessed_at`, `list_frameworks`, `findings_by_severity`, `findings_by_source`, `latest_snapshot_date`, `framework_avg_scores_at`, `effectiveness_latest`.

Both `allowed_frameworks` AND `allowed_system_profiles` must be supported. The spec's posture snapshot grain is `(framework, control_id, system_profile_id, snapshot_date)` — both dimensions need filtering. For methods that query tables without `system_profile_id` (e.g., findings, connector runs), only `allowed_frameworks` applies.

- [ ] **Step 3: Update repository methods to pass scope through**

In `warlock/db/repository.py`, where lake_reads_enabled delegates to LakeReaders, extract the user's framework scope from the scope_filter and pass as `allowed_frameworks`.

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

---

## Task 5: SHA-256 Hash Sampling in Reconciliation

**Files:**
- Modify: `warlock/lake/reconciliation.py`
- Test: `tests/test_lake_hardening.py`

- [ ] **Step 1: Write test**

```python
class TestHashReconciliation:
    def test_hash_sampling_matching(self):
        """Hash samples should match between OLTP and lake when data is identical."""
        from warlock.lake.reconciliation import ReconciliationResult, sample_hashes
        # This tests the hash comparison logic, not full OLTP-lake integration
        oltp_hashes = {"evt-1": "abc123", "evt-2": "def456"}
        lake_hashes = {"evt-1": "abc123", "evt-2": "def456"}
        mismatches = sample_hashes(oltp_hashes, lake_hashes)
        assert len(mismatches) == 0

    def test_hash_sampling_mismatch(self):
        from warlock.lake.reconciliation import sample_hashes
        oltp_hashes = {"evt-1": "abc123", "evt-2": "def456"}
        lake_hashes = {"evt-1": "abc123", "evt-2": "WRONG"}
        mismatches = sample_hashes(oltp_hashes, lake_hashes)
        assert len(mismatches) == 1
        assert mismatches[0]["id"] == "evt-2"
```

- [ ] **Step 2: Implement hash sampling**

Add to `warlock/lake/reconciliation.py`:

```python
def sample_hashes(oltp_hashes: dict[str, str], lake_hashes: dict[str, str]) -> list[dict]:
    """Compare SHA-256 hashes between OLTP and lake records.

    Returns list of mismatched records with id, oltp_hash, lake_hash.
    """
    mismatches = []
    for record_id, oltp_hash in oltp_hashes.items():
        lake_hash = lake_hashes.get(record_id)
        if lake_hash is None:
            mismatches.append({"id": record_id, "oltp_hash": oltp_hash, "lake_hash": None, "reason": "missing_in_lake"})
        elif oltp_hash != lake_hash:
            mismatches.append({"id": record_id, "oltp_hash": oltp_hash, "lake_hash": lake_hash, "reason": "hash_mismatch"})
    return mismatches


def _sample_oltp_hashes(session, table_name: str, sample_size: int = 100) -> dict[str, str]:
    """Read a sample of SHA-256 hashes from OLTP."""
    from warlock.db.models import RawEvent, Finding
    model_map = {"raw_events": RawEvent, "findings": Finding}
    model = model_map.get(table_name)
    if not model or not hasattr(model, "sha256"):
        return {}
    rows = session.query(model.id, model.sha256).limit(sample_size).all()
    return {str(r[0]): str(r[1]) for r in rows if r[1]}


def _sample_lake_hashes(lake_path: str, table_name: str, ids: list[str]) -> dict[str, str]:
    """Read SHA-256 hashes from lake for specific record IDs."""
    from warlock.lake.query import LakeQueryEngine
    from pathlib import Path

    zone_map = {"raw_events": "raw", "findings": "enrichment"}
    zone = zone_map.get(table_name)
    if not zone:
        return {}

    base = Path(lake_path)
    glob = str(base / zone / "**" / "*.parquet")
    if not list(base.glob(f"{zone}/**/*.parquet")):
        return {}

    engine = LakeQueryEngine(lake_path)
    try:
        placeholders = ", ".join("?" for _ in ids)
        result = engine.query(f"""
            SELECT id, sha256
            FROM read_parquet('{glob}', union_by_name=true)
            WHERE id IN ({placeholders})
        """, ids)
        return {r["id"]: r["sha256"] for r in result}
    finally:
        engine.close()
```

Add hash sampling to the existing `reconcile()` function.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

## Task 6: Typed Parquet Columns

**Files:**
- Modify: `warlock/lake/domains.py` (replace string coercion with typed PyArrow schemas)
- Modify: `warlock/lake/zones.py` (preserve existing typed columns, fix any remaining strings)
- Test: `tests/test_lake_hardening.py`

- [ ] **Step 1: Write test**

```python
class TestTypedParquetColumns:
    def test_domain_writer_preserves_numeric_types(self, tmp_path):
        """Numeric fields should be stored as numbers, not strings."""
        from warlock.lake.domains import write_risk_facts
        from warlock.lake.query import LakeQueryEngine

        risk_sims = [{"id": "rs-1", "framework": "nist_800_53", "scenario_name": "breach",
                       "mean_ale": 500000.0, "var_95": 1200000.0, "var_99": 2500000.0,
                       "control_effectiveness": 0.85, "created_at": "2026-03-21"}]
        write_risk_facts(str(tmp_path), "run-1", risk_simulations=risk_sims)

        engine = LakeQueryEngine(str(tmp_path))
        result = engine.query(f"SELECT mean_ale, typeof(mean_ale) as t FROM read_parquet('{tmp_path}/curated/risk_simulations/**/*.parquet')")
        # Should NOT be VARCHAR — should be DOUBLE or FLOAT
        assert result[0]["t"] != "VARCHAR", f"mean_ale stored as {result[0]['t']}, expected numeric"
        engine.close()
```

- [ ] **Step 2: Update `_write_table()` in domains.py**

Replace the generic string coercion with type-aware column building:

```python
def _write_table(lake_path: str, table_name: str, rows: list[dict], run_id: str,
                 partition_key: str | None = None) -> int:
    """Write a list of dicts as a Parquet file with native types."""
    if not rows:
        return 0

    import pyarrow as pa
    import pyarrow.parquet as pq

    # Build columns preserving native types
    columns: dict[str, list] = {}
    for key in rows[0]:
        values = [r.get(key) for r in rows]
        # Detect type from first non-None value
        sample = next((v for v in values if v is not None), "")
        if isinstance(sample, bool):
            columns[key] = [bool(v) if v is not None else False for v in values]
        elif isinstance(sample, int):
            columns[key] = [int(v) if v is not None else 0 for v in values]
        elif isinstance(sample, float):
            columns[key] = [float(v) if v is not None else 0.0 for v in values]
        else:
            columns[key] = [str(v) if v is not None else "" for v in values]

    # Add run_id
    columns["run_id"] = [run_id] * len(rows)

    table = pa.table(columns)
    # ... rest of write logic unchanged
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

## Task 7: Bridge Tables

**Files:**
- Create: `warlock/lake/bridges.py`
- Test: `tests/test_lake_hardening.py`

6 bridge tables from the spec: `bridge_control_crosswalk`, `bridge_entity_relationship`, `fact_data_flow`, `fact_boundary_membership`, `bridge_incident_control`, `bridge_incident_entity`.

- [ ] **Step 1: Write tests**

```python
class TestBridgeTables:
    def test_write_crosswalk_bridge(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        crosswalks = [{"source_framework": "nist_800_53", "source_control": "AC-2",
                       "target_framework": "iso_27001", "target_control": "A.9.2.1",
                       "confidence": 0.95}]
        count = write_bridge_tables(str(tmp_path), "run-1", crosswalks=crosswalks)
        assert count == 1

    def test_write_incident_bridges(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        incident_controls = [{"incident_id": "inc-1", "control_id": "AC-2",
                              "framework": "nist_800_53", "failure_type": "bypassed"}]
        incident_entities = [{"incident_id": "inc-1", "entity_id": "srv-1",
                              "entity_type": "server", "impact": "compromised"}]
        count = write_bridge_tables(str(tmp_path), "run-1",
                                     incident_controls=incident_controls,
                                     incident_entities=incident_entities)
        assert count == 2

    def test_write_entity_relationships(self, tmp_path):
        from warlock.lake.bridges import write_bridge_tables
        relationships = [{"source_entity": "user-1", "target_entity": "laptop-1",
                          "relationship_type": "owns", "effective_date": "2026-03-21"}]
        count = write_bridge_tables(str(tmp_path), "run-1", entity_relationships=relationships)
        assert count == 1
```

- [ ] **Step 2: Implement bridge table writers**

```python
"""Bridge table writers for cross-domain relationships.

Bridge tables connect entities across curated zone domains:
- Crosswalks: framework-to-framework control mappings
- Entity relationships: graph model for blast radius analysis
- Incident bridges: which controls/entities were affected by incidents
"""
```

Follow the same `_write_table()` pattern from domains.py.

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

## Task 8: SCD Type 2 for Entity Dimensions

**Files:**
- Create: `warlock/lake/scd.py`
- Modify: `warlock/lake/domains.py` (update `write_entity_facts`)
- Test: `tests/test_lake_hardening.py`

- [ ] **Step 1: Write test**

```python
class TestSCDType2:
    def test_scd_closes_previous_record(self, tmp_path):
        from warlock.lake.scd import apply_scd_type2
        existing = [{"id": "p-1", "email": "alice@co.com", "department": "eng",
                     "valid_from": "2026-01-01", "valid_to": "9999-12-31", "is_current": "true"}]
        incoming = [{"id": "p-1", "email": "alice@co.com", "department": "security",
                     "valid_from": "2026-03-21", "valid_to": "9999-12-31", "is_current": "true"}]
        result = apply_scd_type2(existing, incoming, key_fields=["id"])
        # Should have 2 records: old (closed) + new (current)
        assert len(result) == 2
        old = next(r for r in result if r["department"] == "eng")
        assert old["is_current"] == "false"
        assert old["valid_to"] == "2026-03-21"
        new = next(r for r in result if r["department"] == "security")
        assert new["is_current"] == "true"
```

- [ ] **Step 2: Implement SCD Type 2 logic**

```python
"""SCD Type 2 (Slowly Changing Dimension) management.

When a dimension record changes, the previous version is closed
(valid_to set to change date, is_current set to false) and a new
version is appended (valid_from set to change date, is_current true).
"""

def apply_scd_type2(
    existing: list[dict],
    incoming: list[dict],
    key_fields: list[str],
    change_date: str | None = None,
) -> list[dict]:
    """Apply SCD Type 2 logic to a set of dimension records."""
    ...
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

## Task 9: Iceberg Catalog Wiring

**Files:**
- Modify: `warlock/lake/catalog.py` (add `IcebergTableManager`)
- Modify: `warlock/lake/schema.py` (add `get_pyarrow_schema()`)
- Modify: `warlock/lake/zones.py` (optionally register tables with Iceberg)
- Test: `tests/test_lake_hardening.py`

This is the biggest task. The approach: keep raw Parquet writes (they work), but also register each table with the Iceberg catalog so Iceberg-aware tools can discover and query them.

- [ ] **Step 1: Write test**

```python
class TestIcebergWiring:
    def test_register_table_with_catalog(self, tmp_path):
        from warlock.lake.catalog import create_catalog, register_table
        catalog = create_catalog("sqlite", str(tmp_path / "catalog.db"))
        # Create a namespace first
        catalog.create_namespace("warlock")
        from warlock.lake.schema import generate_iceberg_schema
        from warlock.db.models import ControlResult
        schema = generate_iceberg_schema(ControlResult)
        table = register_table(catalog, "warlock", "control_results", schema,
                               location=str(tmp_path / "curated" / "control_results"))
        assert table is not None
```

- [ ] **Step 2: Implement table registration**

Add to `warlock/lake/catalog.py`:
```python
def register_table(catalog, namespace: str, table_name: str, schema, location: str):
    """Register or update a table in the Iceberg catalog."""
    from pyiceberg.exceptions import NoSuchTableError
    identifier = (namespace, table_name)
    try:
        return catalog.load_table(identifier)
    except NoSuchTableError:
        return catalog.create_table(identifier, schema=schema, location=location)
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

## Task 10: RAG Over Curated Zone

**Files:**
- Create: `warlock/lake/rag.py` (lake-backed RAG that indexes curated zone)
- Test: `tests/test_lake_hardening.py`

Build a RAG module that reads curated zone data and provides context for AI queries. Uses the existing TF-IDF embedder (no API keys needed for dev) to embed control descriptions, assessment results, and findings.

- [ ] **Step 1: Write test**

```python
class TestLakeRAG:
    def test_index_curated_zone(self, seeded_lake_for_readers):
        from warlock.lake.rag import LakeRAG
        rag = LakeRAG(seeded_lake_for_readers)
        rag.index()
        assert rag.document_count > 0

    def test_query_rag(self, seeded_lake_for_readers):
        from warlock.lake.rag import LakeRAG
        rag = LakeRAG(seeded_lake_for_readers)
        rag.index()
        results = rag.query("access control compliance")
        assert len(results) > 0
```

- [ ] **Step 2: Implement lake RAG**

```python
"""RAG over the curated zone — semantic search over compliance data.

Indexes control results, findings, and framework data from the lake.
Uses TF-IDF embeddings by default (no API key needed). Can upgrade
to OpenAI/Anthropic embeddings for better quality.
"""
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

## Task 11: Final QA Gate

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 500+ passed

- [ ] **Step 2: Run demo seed**

Run: `rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py 2>&1 | grep -E "Connectors succeeded|failed"`
Expected: 57 connectors succeeded, 0 failed

- [ ] **Step 3: Run demo seed with lake + reconciliation**

```bash
rm -f warlock.db && rm -rf lake/
.venv/bin/alembic upgrade head
WLK_LAKE_ENABLED=true .venv/bin/python scripts/demo_seed.py
.venv/bin/python -c "
from warlock.db.engine import get_session
from warlock.lake.reconciliation import reconcile
with get_session() as s:
    r = reconcile(s, 'lake')
print('Reconciliation:', 'PASSED' if r.passed else 'FAILED')
"
```
Expected: PASSED

- [ ] **Step 4: Commit all remaining changes**

---

## Completion Criteria

- [ ] Zero duplicate utility functions (utils.py centralized)
- [ ] Posture snapshot readers return real data from lake
- [ ] Legal hold checking blocks maintenance and thinning
- [ ] ABAC `allowed_frameworks` filter on all analytical lake readers
- [ ] SHA-256 hash sampling in reconciliation
- [ ] Numeric Parquet columns stored as numbers, not strings
- [ ] 6 bridge table writers implemented
- [ ] SCD Type 2 apply logic for entity dimensions
- [ ] Iceberg catalog table registration
- [ ] RAG indexes and queries curated zone data
- [ ] Demo seed unchanged (57 connectors, 0 failed)
- [ ] All 486+ existing tests pass + new tests
