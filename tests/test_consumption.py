"""Tests for consumption tier — 5 output paths."""
from datetime import datetime, timezone
from pathlib import Path
import pytest


@pytest.fixture
def seeded_lake_for_consumption(tmp_path):
    """Seed lake for consumption tier testing."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    date = "2026-03-21"

    cr = {
        "id": ["cr-1", "cr-2", "cr-3"],
        "finding_id": ["f-1", "f-2", "f-3"],
        "control_mapping_id": ["cm-1", "cm-2", "cm-3"],
        "framework": ["nist_800_53", "soc2", "iso_27001"],
        "control_id": ["AC-2", "CC6.1", "A.9.1"],
        "status": ["compliant", "non_compliant", "compliant"],
        "severity": ["high", "critical", "medium"],
        "assertion_name": ["mfa", "encrypt", "access"],
        "assertion_passed": [True, False, True],
        "assessed_at": [datetime.now(timezone.utc).isoformat()] * 3,
        "run_id": ["run-1"] * 3,
    }
    for fw in ["nist_800_53", "soc2", "iso_27001"]:
        d = Path(tmp_path) / "curated" / "control_results" / fw / date
        d.mkdir(parents=True, exist_ok=True)
        fw_data = {k: [v for v, f in zip(cr[k], cr["framework"]) if f == fw] for k in cr}
        pq.write_table(pa.table(fw_data), str(d / "run-1.parquet"))

    cm = {
        "id": ["cm-1", "cm-2", "cm-3"],
        "finding_id": ["f-1", "f-2", "f-3"],
        "framework": ["nist_800_53", "soc2", "iso_27001"],
        "control_id": ["AC-2", "CC6.1", "A.9.1"],
        "control_family": ["AC", "CC6", "A.9"],
        "mapping_method": ["explicit", "explicit", "keyword"],
        "confidence": [1.0, 1.0, 0.8],
        "created_at": [datetime.now(timezone.utc).isoformat()] * 3,
        "run_id": ["run-1"] * 3,
    }
    d = Path(tmp_path) / "curated" / "control_mappings" / date
    d.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(cm), str(d / "run-1.parquet"))

    conn = {
        "id": ["conn-1"],
        "connector_name": ["aws"],
        "source": ["aws"],
        "source_type": ["cloud"],
        "provider": ["aws"],
        "status": ["success"],
        "event_count": [3],
        "error_count": [0],
        "started_at": [datetime.now(timezone.utc).isoformat()],
        "completed_at": [datetime.now(timezone.utc).isoformat()],
        "duration_seconds": [1.0],
        "run_id": ["run-1"],
    }
    d = Path(tmp_path) / "curated" / "connector_runs" / date
    d.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.table(conn), str(d / "run-1.parquet"))

    return str(tmp_path)


class TestGRCToolExport:
    def test_generic_export(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import export_for_grc_tool
        result = export_for_grc_tool(seeded_lake_for_consumption)
        assert len(result) == 3

    def test_vanta_export(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import export_for_grc_tool
        result = export_for_grc_tool(seeded_lake_for_consumption, tool="vanta")
        assert all("test_name" in r for r in result)
        assert all("status" in r for r in result)

    def test_drata_export(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import export_for_grc_tool
        result = export_for_grc_tool(seeded_lake_for_consumption, tool="drata")
        assert all("compliance_status" in r for r in result)

    def test_framework_filter(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import export_for_grc_tool
        result = export_for_grc_tool(seeded_lake_for_consumption, framework="nist_800_53")
        assert all(r["framework"] == "nist_800_53" for r in result)

    def test_empty_lake(self, tmp_path):
        from warlock.lake.consumption import export_for_grc_tool
        result = export_for_grc_tool(str(tmp_path))
        assert result == []


class TestBIQuery:
    def test_execute_query(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import execute_bi_query
        from pathlib import Path
        glob = str(Path(seeded_lake_for_consumption) / "curated" / "control_results" / "**" / "*.parquet")
        result = execute_bi_query(seeded_lake_for_consumption, f"SELECT COUNT(*) as cnt FROM read_parquet('{glob}', union_by_name=true)")
        assert result[0]["cnt"] == 3

    def test_available_tables(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import get_available_tables
        tables = get_available_tables(seeded_lake_for_consumption)
        assert len(tables) > 0
        assert all("zone" in t for t in tables)


class TestRegulatoryFiling:
    def test_gdpr_dpa(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import generate_regulatory_filing
        result = generate_regulatory_filing(seeded_lake_for_consumption, "gdpr_dpa")
        assert result["filing_type"] == "gdpr_dpa"
        assert "sections" in result
        assert result["status"] == "draft"

    def test_sec_8k(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import generate_regulatory_filing
        result = generate_regulatory_filing(seeded_lake_for_consumption, "sec_8k")
        assert result["filing_type"] == "sec_8k"

    def test_unknown_type(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import generate_regulatory_filing
        result = generate_regulatory_filing(seeded_lake_for_consumption, "invalid")
        assert "error" in result


class TestQuestionnaireAutomation:
    def test_sig_autofill(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import auto_fill_questionnaire
        result = auto_fill_questionnaire(seeded_lake_for_consumption, "sig")
        assert len(result) > 0
        assert all("question" in r and "answer" in r for r in result)

    def test_caiq_autofill(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import auto_fill_questionnaire
        result = auto_fill_questionnaire(seeded_lake_for_consumption, "caiq")
        assert len(result) > 0

    def test_ddq_autofill(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import auto_fill_questionnaire
        result = auto_fill_questionnaire(seeded_lake_for_consumption, "ddq")
        assert len(result) > 0


class TestTrustCenter:
    def test_generate_trust_center(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import generate_trust_center_data
        result = generate_trust_center_data(seeded_lake_for_consumption)
        assert "posture_badges" in result
        assert "artifacts" in result
        assert "last_updated" in result
        assert len(result["posture_badges"]) == 3

    def test_badges_status(self, seeded_lake_for_consumption):
        from warlock.lake.consumption import generate_trust_center_data
        result = generate_trust_center_data(seeded_lake_for_consumption)
        # nist and iso have 1 compliant each (100%), soc2 has 1 non-compliant (0%)
        assert result["posture_badges"]["nist_800_53"]["status"] == "compliant"
        assert result["posture_badges"]["soc2"]["status"] == "needs_attention"
