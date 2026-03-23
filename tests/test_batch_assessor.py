"""Tests for batch aggregate control assessment."""

from datetime import datetime, timezone
import pytest

pytest.importorskip("pyarrow")


@pytest.fixture
def seeded_lake_for_assess(tmp_path):
    """Seed a lake with control results for assessment testing."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    from pathlib import Path

    date = "2026-03-21"

    # Control results — mix of statuses for majority voting
    cr_data = {
        "id": ["cr-1", "cr-2", "cr-3", "cr-4", "cr-5", "cr-6"],
        "finding_id": ["f-1", "f-2", "f-3", "f-4", "f-5", "f-6"],
        "control_mapping_id": ["cm-1", "cm-2", "cm-3", "cm-4", "cm-5", "cm-6"],
        "framework": ["nist_800_53", "nist_800_53", "nist_800_53", "soc2", "soc2", "soc2"],
        "control_id": ["AC-2", "AC-2", "AC-2", "CC6.1", "CC6.1", "CC6.1"],
        "status": [
            "compliant",
            "compliant",
            "non_compliant",
            "non_compliant",
            "non_compliant",
            "compliant",
        ],
        "severity": ["high", "medium", "high", "critical", "high", "medium"],
        "assertion_name": ["mfa", "rbac", "mfa", "encrypt", "encrypt", "encrypt"],
        "assertion_passed": [True, True, False, False, False, True],
        "assessed_at": [datetime.now(timezone.utc).isoformat()] * 6,
        "run_id": ["run-1"] * 6,
    }

    for fw in ["nist_800_53", "soc2"]:
        out_dir = Path(tmp_path) / "curated" / "control_results" / fw / date
        out_dir.mkdir(parents=True, exist_ok=True)
        fw_data = {
            k: [v for v, f in zip(cr_data[k], cr_data["framework"]) if f == fw] for k in cr_data
        }
        pq.write_table(pa.table(fw_data), str(out_dir / "run-1.parquet"))

    return str(tmp_path)


class TestBatchAssessor:
    def test_aggregate_returns_results(self, seeded_lake_for_assess):
        from warlock.lake.batch_assessor import aggregate_control_statuses

        results = aggregate_control_statuses(seeded_lake_for_assess)
        assert len(results) == 2  # AC-2 and CC6.1

    def test_majority_voting_compliant(self, seeded_lake_for_assess):
        """AC-2 has 2 compliant + 1 non_compliant → majority compliant."""
        from warlock.lake.batch_assessor import aggregate_control_statuses

        results = aggregate_control_statuses(seeded_lake_for_assess)
        ac2 = next(r for r in results if r["control_id"] == "AC-2")
        assert ac2["aggregate_status"] == "compliant"
        assert ac2["compliant_count"] == 2
        assert ac2["non_compliant_count"] == 1

    def test_majority_voting_non_compliant(self, seeded_lake_for_assess):
        """CC6.1 has 2 non_compliant + 1 compliant → majority non_compliant."""
        from warlock.lake.batch_assessor import aggregate_control_statuses

        results = aggregate_control_statuses(seeded_lake_for_assess)
        cc61 = next(r for r in results if r["control_id"] == "CC6.1")
        assert cc61["aggregate_status"] == "non_compliant"

    def test_write_aggregate_assessments(self, seeded_lake_for_assess):
        from warlock.lake.batch_assessor import (
            aggregate_control_statuses,
            write_aggregate_assessments,
        )

        aggregates = aggregate_control_statuses(seeded_lake_for_assess)
        written = write_aggregate_assessments(seeded_lake_for_assess, aggregates)
        assert written == 2

    def test_empty_lake(self, tmp_path):
        from warlock.lake.batch_assessor import aggregate_control_statuses

        results = aggregate_control_statuses(str(tmp_path))
        assert results == []

    def test_determine_status_all_compliant(self):
        from warlock.lake.batch_assessor import _determine_aggregate_status

        assert _determine_aggregate_status(10, 0, 0, 0, 10) == "compliant"

    def test_determine_status_all_non_compliant(self):
        from warlock.lake.batch_assessor import _determine_aggregate_status

        assert _determine_aggregate_status(0, 10, 0, 0, 10) == "non_compliant"

    def test_determine_status_partial(self):
        from warlock.lake.batch_assessor import _determine_aggregate_status

        assert _determine_aggregate_status(3, 3, 4, 0, 10) == "partial"

    def test_determine_status_empty(self):
        from warlock.lake.batch_assessor import _determine_aggregate_status

        assert _determine_aggregate_status(0, 0, 0, 0, 0) == "not_assessed"
