# Data Lake Phase 3: Steady State — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reposition the AI layer from inline pipeline Stage 4 to a lake consumer, add batch aggregate control assessment, `warlock ask` CLI command, and lake-native OSCAL export.

**Architecture:** AI becomes a post-pipeline consumer that reads from the curated zone with full cross-domain context (all findings, mappings, trends for a control). A new `warlock ask` CLI enables conversational compliance queries. OSCAL exports read directly from the lake. OLTP stops writing historical analytical data.

**Tech Stack:** Existing AI service (httpx → Anthropic/OpenAI/Gemini), DuckDB lake readers, existing OSCAL exporter

**Spec:** `docs/superpowers/specs/2026-03-21-grc-data-lake-design.md` (Section 8, Phase 3)

**Depends on:** Phase 2 complete (lake readers, shadow validation, feature flags, aggregation tables). 385 tests passing.

**Acceptance criteria:**
- Batch AI assessment reads full context from lake curated zone
- `warlock ask` CLI answers compliance questions using lake data
- OSCAL export reads from lake when enabled
- Demo seed unchanged (57 connectors, 0 failed)
- All 385+ tests pass

---

## File Structure

### New Files

| File | Responsibility |
|---|---|
| `warlock/lake/batch_assessor.py` | Batch AI assessment over curated zone — aggregate per-control reasoning |
| `warlock/lake/ask.py` | Conversational compliance query engine — lake-backed Q&A |
| `tests/test_batch_assessor.py` | Tests for batch assessment + ask CLI |

### Modified Files

| File | What Changes |
|---|---|
| `warlock/ai/types.py` | Add `AITask.AGGREGATE_CONTROL_ASSESSMENT` and `AITask.COMPLIANCE_QUERY` |
| `warlock/ai/service.py` | Add prompt templates for new task types |
| `warlock/cli/lake.py` | Add `lake assess` and `lake query` commands |
| `warlock/cli/ai_cmd.py` | Add `warlock ask` command (alias for lake query) |
| `warlock/export/oscal.py` | Add lake-native export path when lake_reads enabled |

---

## Task 1: Add AI Task Types for Lake Consumer

**Files:**
- Modify: `warlock/ai/types.py`

- [ ] **Step 1: Add new task types to AITask enum**

```python
AGGREGATE_CONTROL_ASSESSMENT = "aggregate_control_assessment"
COMPLIANCE_QUERY = "compliance_query"
```

- [ ] **Step 2: Run tests**
- [ ] **Step 3: Commit**

---

## Task 2: Batch AI Control Assessment

**Files:**
- Create: `warlock/lake/batch_assessor.py`
- Create: `tests/test_batch_assessor.py`

The batch assessor reads from the lake curated zone, groups control results by (framework, control_id), builds full context, and optionally calls AI for aggregate reasoning.

- [ ] **Step 1: Write tests**

```python
class TestBatchAssessor:
    def test_aggregate_control_status_from_lake(self, seeded_lake):
        """Aggregate status computed from lake control results."""
        from warlock.lake.batch_assessor import aggregate_control_statuses
        results = aggregate_control_statuses(seeded_lake)
        assert len(results) > 0
        for r in results:
            assert "framework" in r
            assert "control_id" in r
            assert "aggregate_status" in r
            assert "total_assessments" in r
            assert "compliant_count" in r

    def test_aggregate_with_majority_voting(self, seeded_lake):
        """Aggregate status uses majority voting across assessments."""
        from warlock.lake.batch_assessor import aggregate_control_statuses
        results = aggregate_control_statuses(seeded_lake)
        # For controls with all compliant findings, status should be compliant
        for r in results:
            if r["compliant_count"] == r["total_assessments"]:
                assert r["aggregate_status"] == "compliant"
```

- [ ] **Step 2: Implement batch_assessor.py**

```python
"""Batch AI control assessment over the curated zone.

Reads control results from the lake, groups by (framework, control_id),
computes aggregate status via majority voting, and optionally calls
the AI service for narrative reasoning.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


def aggregate_control_statuses(lake_path: str) -> list[dict[str, Any]]:
    """Compute aggregate status per control from lake data.

    Majority voting: if >50% of assessments are compliant, aggregate is compliant.
    Falls back to 'partial' if no clear majority.
    """
    from warlock.lake.query import LakeQueryEngine
    from pathlib import Path

    engine = LakeQueryEngine(lake_path)
    base = Path(lake_path)
    cr_glob = str(base / "curated" / "control_results" / "**" / "*.parquet")

    try:
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
        aggregates.append({
            "framework": row["framework"],
            "control_id": row["control_id"],
            "aggregate_status": status,
            "total_assessments": total,
            "compliant_count": row["compliant_count"],
            "non_compliant_count": row["non_compliant_count"],
            "partial_count": row["partial_count"],
            "not_assessed_count": row["not_assessed_count"],
            "last_assessed": row["last_assessed"],
            "computed_at": datetime.now(timezone.utc).isoformat(),
        })

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
    """Write aggregate assessments to curated zone."""
    if not aggregates:
        return 0

    import pyarrow as pa
    import pyarrow.parquet as pq
    from pathlib import Path

    base = Path(lake_path) / "curated" / "aggregate_control_assessments"
    base.mkdir(parents=True, exist_ok=True)

    table = pa.table({k: [r[k] for r in aggregates] for k in aggregates[0]})
    pq.write_table(table, str(base / "latest.parquet"))
    log.info("Wrote %d aggregate assessments to %s", len(aggregates), base)
    return len(aggregates)
```

- [ ] **Step 3: Run tests**
- [ ] **Step 4: Commit**

---

## Task 3: `warlock ask` — Conversational Compliance Queries

**Files:**
- Create: `warlock/lake/ask.py`
- Modify: `warlock/cli/lake.py` — add `lake query` command
- Modify: `warlock/cli/ai_cmd.py` — add `ask` command

- [ ] **Step 1: Implement lake ask engine**

```python
"""Conversational compliance query engine.

Answers natural language compliance questions by querying the lake
curated zone and optionally using AI to generate narrative responses.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)


def query_lake(lake_path: str, question: str) -> dict[str, Any]:
    """Answer a compliance question using lake data.

    Determines the type of question and routes to the appropriate
    lake query. Returns structured data that can be rendered by
    the CLI or API.
    """
    question_lower = question.lower()

    if any(kw in question_lower for kw in ["posture", "compliance", "status", "ready"]):
        return _query_posture(lake_path, question)
    elif any(kw in question_lower for kw in ["finding", "vulnerability", "risk"]):
        return _query_findings(lake_path, question)
    elif any(kw in question_lower for kw in ["connector", "source", "collection"]):
        return _query_connectors(lake_path, question)
    elif any(kw in question_lower for kw in ["framework", "control"]):
        return _query_frameworks(lake_path, question)
    else:
        return _query_general(lake_path, question)


def _query_posture(lake_path: str, question: str) -> dict[str, Any]:
    """Answer posture/compliance questions."""
    from warlock.lake.readers import LakeReaders
    readers = LakeReaders(lake_path)
    try:
        summary = readers.dashboard_framework_summary()
        frameworks = readers.distinct_frameworks()
        return {
            "type": "posture_summary",
            "frameworks": len(frameworks),
            "summary": summary,
            "answer": f"Tracking {len(frameworks)} frameworks with {sum(r[2] for r in summary)} total control assessments.",
        }
    finally:
        readers.close()


def _query_findings(lake_path: str, question: str) -> dict[str, Any]:
    """Answer finding/vulnerability questions."""
    from warlock.lake.readers import LakeReaders
    readers = LakeReaders(lake_path)
    try:
        critical = readers.findings_by_severity("critical", limit=5)
        high = readers.findings_by_severity("high", limit=5)
        return {
            "type": "findings_summary",
            "critical_count": len(critical),
            "high_count": len(high),
            "answer": f"Found {len(critical)} critical and {len(high)} high severity findings.",
        }
    finally:
        readers.close()


def _query_connectors(lake_path: str, question: str) -> dict[str, Any]:
    """Answer connector/collection questions."""
    from warlock.lake.readers import LakeReaders
    readers = LakeReaders(lake_path)
    try:
        connectors = readers.latest_per_connector()
        total = readers.total_event_count()
        return {
            "type": "connector_summary",
            "connector_count": len(connectors),
            "total_events": total,
            "answer": f"{len(connectors)} connectors collected {total} total events.",
        }
    finally:
        readers.close()


def _query_frameworks(lake_path: str, question: str) -> dict[str, Any]:
    """Answer framework/control questions."""
    from warlock.lake.readers import LakeReaders
    readers = LakeReaders(lake_path)
    try:
        frameworks = readers.list_frameworks()
        return {
            "type": "framework_summary",
            "frameworks": frameworks,
            "answer": f"Tracking {len(frameworks)} frameworks: {', '.join(f[0] for f in frameworks[:5])}{'...' if len(frameworks) > 5 else ''}",
        }
    finally:
        readers.close()


def _query_general(lake_path: str, question: str) -> dict[str, Any]:
    """General fallback — provide an overview."""
    from warlock.lake.readers import LakeReaders
    readers = LakeReaders(lake_path)
    try:
        summary = readers.dashboard_framework_summary()
        frameworks = readers.distinct_frameworks()
        total_events = readers.total_event_count()
        return {
            "type": "general_overview",
            "frameworks": len(frameworks),
            "total_assessments": sum(r[2] for r in summary),
            "total_events": total_events,
            "answer": f"Warlock lake: {len(frameworks)} frameworks, {sum(r[2] for r in summary)} assessments, {total_events} events collected.",
        }
    finally:
        readers.close()
```

- [ ] **Step 2: Add CLI commands**

Add to `warlock/cli/lake.py`:
```python
@lake.command("query")
@click.argument("question")
@click.option("--path", default=None)
def lake_query(question: str, path: str | None) -> None:
    """Query the lake with a natural language question."""
    from warlock.config import get_settings
    from warlock.lake.ask import query_lake
    settings = get_settings()
    lake_path = path or settings.lake_path
    result = query_lake(lake_path, question)
    console.print(f"\n[cyan]{result['answer']}[/cyan]\n")
```

Add to `warlock/cli/ai_cmd.py` (or as a top-level command):
```python
@cli.command("ask")
@click.argument("question")
def ask(question: str) -> None:
    """Ask a compliance question (queries the data lake)."""
    from warlock.config import get_settings
    from warlock.lake.ask import query_lake
    settings = get_settings()
    result = query_lake(settings.lake_path, question)
    console.print(f"\n[cyan]{result['answer']}[/cyan]\n")
```

- [ ] **Step 3: Write tests**
- [ ] **Step 4: Run tests**
- [ ] **Step 5: Commit**

---

## Task 4: Lake `assess` CLI Command

**Files:**
- Modify: `warlock/cli/lake.py`

- [ ] **Step 1: Add assess command**

```python
@lake.command("assess")
@click.option("--path", default=None)
@click.option("--framework", default=None, help="Limit to specific framework")
def lake_assess(path: str | None, framework: str | None) -> None:
    """Run batch aggregate control assessment from lake data."""
    from warlock.config import get_settings
    from warlock.lake.batch_assessor import aggregate_control_statuses, write_aggregate_assessments
    settings = get_settings()
    lake_path = path or settings.lake_path

    console.print("[cyan]Computing aggregate control assessments from lake...[/cyan]")
    aggregates = aggregate_control_statuses(lake_path)

    if framework:
        aggregates = [a for a in aggregates if a["framework"] == framework]

    written = write_aggregate_assessments(lake_path, aggregates)
    console.print(f"[green]{written} aggregate assessments written.[/green]")

    # Summary
    from rich.table import Table
    table = Table(title="Aggregate Control Assessments")
    table.add_column("Framework")
    table.add_column("Controls", justify="right")
    table.add_column("Compliant", justify="right")
    table.add_column("Non-Compliant", justify="right")
    table.add_column("Partial", justify="right")

    from collections import Counter
    by_fw = {}
    for a in aggregates:
        fw = a["framework"]
        if fw not in by_fw:
            by_fw[fw] = Counter()
        by_fw[fw][a["aggregate_status"]] += 1

    for fw in sorted(by_fw):
        c = by_fw[fw]
        table.add_row(
            fw,
            str(sum(c.values())),
            str(c.get("compliant", 0)),
            str(c.get("non_compliant", 0)),
            str(c.get("partial", 0)),
        )
    console.print(table)
```

- [ ] **Step 2: Run full test suite**
- [ ] **Step 3: Commit**

---

## Task 5: Lake-Native OSCAL Export Path

**Files:**
- Modify: `warlock/export/oscal.py`

- [ ] **Step 1: Add lake read path to OSCAL export**

At the top of the OSCAL generation function, add a check for lake reads:

```python
from warlock.config import get_settings
settings = get_settings()
if settings.lake_reads_enabled("oscal_export"):
    # Read control results from lake for OSCAL export
    from warlock.lake.readers import LakeReaders
    readers = LakeReaders(settings.lake_path)
    try:
        results = readers.dashboard_framework_summary()
        # Use lake data for OSCAL generation
    finally:
        readers.close()
```

This follows the same feature flag pattern from Phase 2.

- [ ] **Step 2: Run tests**
- [ ] **Step 3: Commit**

---

## Task 6: Final QA Gate + Phase 3 Completion

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -x -q`
Expected: 395+ passed

- [ ] **Step 2: Run demo seed**

Run: `rm -f warlock.db && .venv/bin/alembic upgrade head && .venv/bin/python scripts/demo_seed.py 2>&1 | grep -E "Connectors succeeded|failed"`
Expected: 57 connectors succeeded, 0 failed

- [ ] **Step 3: Run demo seed with lake + assess**

```bash
rm -f warlock.db && rm -rf lake/
.venv/bin/alembic upgrade head
WLK_LAKE_ENABLED=true .venv/bin/python scripts/demo_seed.py
.venv/bin/python -c "from warlock.lake.batch_assessor import aggregate_control_statuses, write_aggregate_assessments; a = aggregate_control_statuses('lake'); write_aggregate_assessments('lake', a); print(f'{len(a)} aggregate assessments')"
```

- [ ] **Step 4: Test ask command**

```bash
.venv/bin/python -c "from warlock.lake.ask import query_lake; r = query_lake('lake', 'What is our compliance posture?'); print(r['answer'])"
```

- [ ] **Step 5: Commit all remaining changes**

---

## Phase 3 Completion Criteria

- [ ] Batch aggregate control assessment reads from lake curated zone
- [ ] `warlock ask` CLI answers compliance questions using lake data
- [ ] `warlock lake assess` CLI computes and writes aggregate assessments
- [ ] `warlock lake query` CLI queries lake with natural language
- [ ] OSCAL export has lake-native path (behind feature flag)
- [ ] Demo seed produces identical output (57 connectors, 0 failed)
- [ ] All 385+ existing tests pass
- [ ] QA gate passes
