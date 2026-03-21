"""Tests for MCP tool interface."""
import pytest

pytest.importorskip("pyarrow")


class TestMCPToolDefinitions:
    def test_get_tools_returns_list(self):
        from warlock.lake.mcp_tools import get_mcp_tools
        tools = get_mcp_tools()
        assert isinstance(tools, list)
        assert len(tools) == 8

    def test_each_tool_has_required_fields(self):
        from warlock.lake.mcp_tools import get_mcp_tools
        for tool in get_mcp_tools():
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool


class TestMCPToolCalls:
    def test_unknown_tool(self, tmp_path):
        from warlock.lake.mcp_tools import call_mcp_tool
        result = call_mcp_tool(str(tmp_path), "nonexistent")
        assert "error" in result

    def test_lake_overview_empty(self, tmp_path):
        from warlock.lake.mcp_tools import call_mcp_tool
        result = call_mcp_tool(str(tmp_path), "lake_overview")
        # Empty lake has no parquet files — result is either a valid overview or an error dict
        assert isinstance(result, dict)

    def test_compliance_posture_with_data(self, seeded_lake_for_mcp):
        from warlock.lake.mcp_tools import call_mcp_tool
        result = call_mcp_tool(seeded_lake_for_mcp, "compliance_posture")
        assert "summary" in result
        assert len(result["summary"]) > 0

    def test_framework_list_with_data(self, seeded_lake_for_mcp):
        from warlock.lake.mcp_tools import call_mcp_tool
        result = call_mcp_tool(seeded_lake_for_mcp, "framework_list")
        assert "frameworks" in result

    def test_control_details_with_data(self, seeded_lake_for_mcp):
        from warlock.lake.mcp_tools import call_mcp_tool
        result = call_mcp_tool(seeded_lake_for_mcp, "control_details", {"framework": "nist_800_53", "control_id": "AC-2"})
        assert "assessments" in result


@pytest.fixture
def seeded_lake_for_mcp(tmp_path):
    """Seed minimal lake for MCP tool testing."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    from datetime import datetime, timezone
    from pathlib import Path

    date = "2026-03-21"

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

    conn = {
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
    pq.write_table(pa.table(conn), str(d / "run-1.parquet"))

    return str(tmp_path)
