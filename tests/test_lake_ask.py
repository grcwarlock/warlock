"""Tests for the conversational compliance query engine."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

pytest.importorskip("pyarrow")


@pytest.fixture
def seeded_lake_for_ask(tmp_path):
    """Minimal seeded lake for ask tests."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    date = "2026-03-21"

    # Control results
    cr = {
        "id": ["cr-1", "cr-2"],
        "finding_id": ["f-1", "f-2"],
        "control_mapping_id": ["cm-1", "cm-2"],
        "framework": ["nist_800_53", "soc2"],
        "control_id": ["AC-2", "CC6.1"],
        "status": ["compliant", "non_compliant"],
        "severity": ["high", "critical"],
        "assertion_name": ["mfa", "encrypt"],
        "assertion_passed": [True, False],
        "assessed_at": [datetime.now(timezone.utc).isoformat()] * 2,
        "run_id": ["run-1"] * 2,
    }
    for fw in ["nist_800_53", "soc2"]:
        d = Path(tmp_path) / "curated" / "control_results" / fw / date
        d.mkdir(parents=True, exist_ok=True)
        fw_data = {k: [v for v, f in zip(cr[k], cr["framework"]) if f == fw] for k in cr}
        pq.write_table(pa.table(fw_data), str(d / "run-1.parquet"))

    # Findings
    f = {
        "id": ["f-1", "f-2"],
        "raw_event_id": ["re-1", "re-2"],
        "observation_type": ["iam", "sg"],
        "title": ["No MFA", "Open SG"],
        "detail": ["", ""],
        "resource_id": ["u-1", "sg-1"],
        "resource_type": ["user", "sg"],
        "source": ["aws", "aws"],
        "source_type": ["cloud", "cloud"],
        "provider": ["aws", "aws"],
        "severity": ["high", "critical"],
        "confidence": [1.0, 1.0],
        "observed_at": [datetime.now(timezone.utc).isoformat()] * 2,
        "ingested_at": [datetime.now(timezone.utc).isoformat()] * 2,
        "sha256": ["abc", "def"],
        "run_id": ["run-1"] * 2,
    }
    d = Path(tmp_path) / "enrichment" / "aws" / date
    d.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(f), str(d / "run-1.parquet"))

    # Connector runs
    c = {
        "id": ["conn-1"],
        "connector_name": ["aws"],
        "source": ["aws"],
        "source_type": ["cloud"],
        "provider": ["aws"],
        "status": ["success"],
        "event_count": [2],
        "error_count": [0],
        "started_at": [datetime.now(timezone.utc).isoformat()],
        "completed_at": [datetime.now(timezone.utc).isoformat()],
        "duration_seconds": [1.0],
        "run_id": ["run-1"],
    }
    d = Path(tmp_path) / "curated" / "connector_runs" / date
    d.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(c), str(d / "run-1.parquet"))

    # Control mappings
    cm = {
        "id": ["cm-1", "cm-2"],
        "finding_id": ["f-1", "f-2"],
        "framework": ["nist_800_53", "soc2"],
        "control_id": ["AC-2", "CC6.1"],
        "control_family": ["AC", "CC6"],
        "mapping_method": ["explicit", "explicit"],
        "confidence": [1.0, 1.0],
        "created_at": [datetime.now(timezone.utc).isoformat()] * 2,
        "run_id": ["run-1"] * 2,
    }
    d = Path(tmp_path) / "curated" / "control_mappings" / date
    d.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(cm), str(d / "run-1.parquet"))

    return str(tmp_path)


class TestQueryLake:
    def test_posture_question(self, seeded_lake_for_ask):
        from warlock.lake.ask import query_lake

        result = query_lake(seeded_lake_for_ask, "What is our compliance posture?")
        assert result["type"] == "posture_summary"
        assert "answer" in result

    def test_findings_question(self, seeded_lake_for_ask):
        from warlock.lake.ask import query_lake

        result = query_lake(seeded_lake_for_ask, "Show me critical findings")
        assert result["type"] in ("findings_summary", "findings_search")

    def test_connector_question(self, seeded_lake_for_ask):
        from warlock.lake.ask import query_lake

        result = query_lake(seeded_lake_for_ask, "How many connectors do we have?")
        assert result["type"] in ("connector_summary", "connector_search")

    def test_framework_question(self, seeded_lake_for_ask):
        from warlock.lake.ask import query_lake

        result = query_lake(seeded_lake_for_ask, "What frameworks are we tracking?")
        assert result["type"] in ("framework_summary", "framework_detail")

    def test_general_question(self, seeded_lake_for_ask):
        from warlock.lake.ask import query_lake

        result = query_lake(seeded_lake_for_ask, "Give me an overview")
        assert result["type"] == "general_overview"
        assert "answer" in result
