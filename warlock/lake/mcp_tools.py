"""MCP tool definitions for the Warlock lake curated zone.

Exposes lake queries as MCP-compatible tool schemas. These tools
enable AI agents to query compliance, risk, evidence, and entity
data from the lake conversationally.

Usage:
    tools = get_mcp_tools()  # Returns list of tool definitions
    result = call_mcp_tool(lake_path, tool_name, arguments)  # Execute a tool
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# MCP tool definitions — each describes a queryable capability
MCP_TOOLS = [
    {
        "name": "compliance_posture",
        "description": "Get compliance posture summary across all frameworks — shows compliant, non-compliant, partial counts per framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Optional: filter to specific framework (e.g., nist_800_53, soc2)",
                },
            },
        },
    },
    {
        "name": "framework_list",
        "description": "List all compliance frameworks being tracked with control counts",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "findings_by_severity",
        "description": "List findings filtered by severity level",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity to filter by",
                },
                "limit": {"type": "integer", "description": "Max results (default 20)"},
            },
            "required": ["severity"],
        },
    },
    {
        "name": "non_compliant_risks",
        "description": "Get top non-compliant controls ranked by finding count — shows highest-risk areas",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "connector_status",
        "description": "Show status of all data connectors — which are collecting, event counts, last run time",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "control_details",
        "description": "Get detailed assessment results for a specific control in a framework",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "description": "Framework ID (e.g., nist_800_53)"},
                "control_id": {"type": "string", "description": "Control ID (e.g., AC-2)"},
            },
            "required": ["framework", "control_id"],
        },
    },
    {
        "name": "aggregate_assessment",
        "description": "Get aggregate AI assessment for controls — majority-voted status across all findings",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Optional: filter to specific framework",
                },
            },
        },
    },
    {
        "name": "lake_overview",
        "description": "Get a high-level overview of the entire compliance lake — frameworks, assessments, events, findings",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def get_mcp_tools() -> list[dict]:
    """Return MCP tool definitions for the lake curated zone."""
    return MCP_TOOLS


def call_mcp_tool(
    lake_path: str, tool_name: str, arguments: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Execute an MCP tool call against the lake.

    Returns a dict with the tool result suitable for MCP response.
    """
    args = arguments or {}

    try:
        handler = _TOOL_HANDLERS.get(tool_name)
        if not handler:
            return {
                "error": f"Unknown tool: {tool_name}",
                "available": [t["name"] for t in MCP_TOOLS],
            }
        return handler(lake_path, args)
    except Exception as exc:
        log.exception("MCP tool %s failed", tool_name)
        return {"error": str(exc)}


def _handle_compliance_posture(lake_path: str, args: dict) -> dict:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        framework = args.get("framework")
        if framework:
            summary = readers.coverage_by_status(framework)
        else:
            summary = readers.dashboard_framework_summary()
        return {
            "frameworks": list({r[0] for r in summary}),
            "summary": [{"framework": r[0], "status": r[1], "count": r[2]} for r in summary],
            "total_assessments": sum(r[2] for r in summary),
        }
    finally:
        readers.close()


def _handle_framework_list(lake_path: str, args: dict) -> dict:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        frameworks = readers.list_frameworks()
        return {"frameworks": [{"name": f[0], "control_count": f[1]} for f in frameworks]}
    finally:
        readers.close()


def _handle_findings_by_severity(lake_path: str, args: dict) -> dict:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        severity = args.get("severity", "critical")
        limit = args.get("limit", 20)
        findings = readers.findings_by_severity(severity, limit=limit)
        return {"severity": severity, "count": len(findings), "findings": findings[:20]}
    finally:
        readers.close()


def _handle_non_compliant_risks(lake_path: str, args: dict) -> dict:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        risks = readers.top_non_compliant_risks()
        return {"risks": risks, "count": len(risks)}
    finally:
        readers.close()


def _handle_connector_status(lake_path: str, args: dict) -> dict:
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        connectors = readers.latest_per_connector()
        total = readers.total_event_count()
        return {"connectors": connectors, "total_events": total, "connector_count": len(connectors)}
    finally:
        readers.close()


def _handle_control_details(lake_path: str, args: dict) -> dict:
    from pathlib import Path

    from warlock.lake.query import LakeQueryEngine

    framework = args.get("framework", "")
    control_id = args.get("control_id", "")
    if not framework or not control_id:
        return {"error": "framework and control_id are required"}

    engine = LakeQueryEngine(lake_path)
    base = Path(lake_path)
    cr_glob = str(base / "curated" / "control_results" / "**" / "*.parquet")

    try:
        results = engine.query(
            f"""
            SELECT id, status, severity, assertion_name, assertion_passed, assessed_at
            FROM read_parquet('{cr_glob}', union_by_name=true)
            WHERE framework = ? AND control_id = ?
            ORDER BY assessed_at DESC
            LIMIT 50
        """,
            [framework, control_id],
        )
        return {
            "framework": framework,
            "control_id": control_id,
            "assessment_count": len(results),
            "assessments": results,
        }
    finally:
        engine.close()


def _handle_aggregate_assessment(lake_path: str, args: dict) -> dict:
    from pathlib import Path

    from warlock.lake.query import LakeQueryEngine

    engine = LakeQueryEngine(lake_path)
    base = Path(lake_path)
    agg_glob = str(base / "curated" / "aggregate_control_assessments" / "*.parquet")

    try:
        if not list(base.glob("curated/aggregate_control_assessments/*.parquet")):
            return {"error": "No aggregate assessments found. Run 'warlock lake assess' first."}

        framework = args.get("framework")
        if framework:
            results = engine.query(
                f"""
                SELECT * FROM read_parquet('{agg_glob}', union_by_name=true)
                WHERE framework = ?
                ORDER BY control_id
            """,
                [framework],
            )
        else:
            results = engine.query(f"""
                SELECT framework, aggregate_status, COUNT(*) as count
                FROM read_parquet('{agg_glob}', union_by_name=true)
                GROUP BY framework, aggregate_status
                ORDER BY framework, count DESC
            """)
        return {"results": results, "count": len(results)}
    finally:
        engine.close()


def _handle_lake_overview(lake_path: str, args: dict) -> dict:
    from warlock.lake.ask import query_lake

    return query_lake(lake_path, "overview")


_TOOL_HANDLERS = {
    "compliance_posture": _handle_compliance_posture,
    "framework_list": _handle_framework_list,
    "findings_by_severity": _handle_findings_by_severity,
    "non_compliant_risks": _handle_non_compliant_risks,
    "connector_status": _handle_connector_status,
    "control_details": _handle_control_details,
    "aggregate_assessment": _handle_aggregate_assessment,
    "lake_overview": _handle_lake_overview,
}
