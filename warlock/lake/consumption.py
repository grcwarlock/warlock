"""Consumption tier — 5 paths for GRC professionals to access lake data.

1. GRC Tool Export — pre-joined views for Vanta, Drata, AuditBoard, ServiceNow
2. BI / Direct Queries — DuckDB query interface for Looker, Metabase, Python/SQL
3. Regulatory Filing — template-driven document generation
4. Questionnaire Automation — auto-fill SIG, CAIQ, DDQ from lake data
5. Trust Center — posture badges and self-service artifacts
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path 1: GRC Tool Export
# ---------------------------------------------------------------------------


def export_for_grc_tool(
    lake_path: str,
    tool: str = "generic",
    framework: str | None = None,
) -> list[dict[str, Any]]:
    """Export pre-joined compliance data for GRC tools (Vanta, Drata, etc).

    Returns a list of dicts with fields:
    - framework, control_id, status, severity, finding_count
    - assertion_name, assessed_at, evidence_count (when available)

    Each GRC tool expects slightly different field names — the 'tool'
    parameter selects the field mapping.
    """
    from warlock.lake.query import LakeQueryEngine

    engine = LakeQueryEngine(lake_path)
    base = Path(lake_path)
    cr_glob = str(base / "curated" / "control_results" / "**" / "*.parquet")
    cm_glob = str(base / "curated" / "control_mappings" / "**" / "*.parquet")

    try:
        if not list(base.glob("curated/control_results/**/*.parquet")):
            return []

        where = "WHERE cr.framework = ?" if framework else ""
        params = [framework] if framework else []

        result = engine.query(
            f"""
            SELECT
                cr.framework,
                cr.control_id,
                cr.status,
                cr.severity,
                COUNT(DISTINCT cr.finding_id) as finding_count,
                cr.assertion_name,
                MAX(cr.assessed_at) as assessed_at,
                cm.mapping_method,
                cm.confidence as mapping_confidence
            FROM read_parquet('{cr_glob}', union_by_name=true) cr
            LEFT JOIN read_parquet('{cm_glob}', union_by_name=true) cm
                ON cr.control_mapping_id = cm.id
            {where}
            GROUP BY cr.framework, cr.control_id, cr.status, cr.severity,
                     cr.assertion_name, cm.mapping_method, cm.confidence
            ORDER BY cr.framework, cr.control_id
        """,
            params,
        )

        # Apply tool-specific field mapping
        if tool == "vanta":
            return [_map_vanta(r) for r in result]
        elif tool == "drata":
            return [_map_drata(r) for r in result]
        elif tool == "auditboard":
            return [_map_auditboard(r) for r in result]
        elif tool == "servicenow":
            return [_map_servicenow(r) for r in result]
        else:
            return result
    finally:
        engine.close()


def _map_vanta(row: dict) -> dict:
    """Map lake fields to Vanta's expected format."""
    return {
        "test_name": f"{row['framework']}/{row['control_id']}",
        "status": "PASS" if row["status"] == "compliant" else "FAIL",
        "last_evaluated": row.get("assessed_at", ""),
        "evidence_count": row.get("finding_count", 0),
    }


def _map_drata(row: dict) -> dict:
    """Map lake fields to Drata's expected format."""
    return {
        "control_id": row["control_id"],
        "framework": row["framework"],
        "compliance_status": row["status"],
        "risk_level": row.get("severity", ""),
        "last_check": row.get("assessed_at", ""),
    }


def _map_auditboard(row: dict) -> dict:
    """Map lake fields to AuditBoard's expected format.

    AuditBoard expects: control_id, test_name, test_status, evidence,
    last_tested, exceptions.
    """
    status = row.get("status", "")
    test_status = {
        "compliant": "Effective",
        "non_compliant": "Ineffective",
        "partial": "Partially Effective",
        "not_assessed": "Not Tested",
    }.get(status, "Not Tested")

    return {
        "control_id": row["control_id"],
        "test_name": f"{row['framework']}/{row['control_id']}",
        "test_status": test_status,
        "evidence": f"{row.get('finding_count', 0)} finding(s) evaluated",
        "last_tested": row.get("assessed_at", ""),
        "exceptions": "Yes" if status == "non_compliant" else "No",
    }


def _map_servicenow(row: dict) -> dict:
    """Map lake fields to ServiceNow GRC expected format.

    ServiceNow expects: cmdb_ci, finding_type, severity, state,
    assignment_group, remediation.
    """
    status = row.get("status", "")
    state_map = {
        "compliant": "Closed",
        "non_compliant": "Open",
        "partial": "Work in Progress",
        "not_assessed": "New",
    }

    return {
        "cmdb_ci": row.get("control_id", ""),
        "finding_type": f"{row['framework']} Control Assessment",
        "severity": _servicenow_severity(row.get("severity", "")),
        "state": state_map.get(status, "New"),
        "assignment_group": f"GRC-{row['framework']}",
        "remediation": (
            "Remediation required"
            if status == "non_compliant"
            else "Monitoring"
            if status == "partial"
            else "No action required"
        ),
    }


def _servicenow_severity(severity: str) -> str:
    """Map internal severity to ServiceNow priority scale (1-4)."""
    return {
        "critical": "1 - Critical",
        "high": "2 - High",
        "medium": "3 - Medium",
        "low": "4 - Low",
        "info": "4 - Low",
    }.get(severity.lower(), "3 - Medium")


# ---------------------------------------------------------------------------
# Path 2: BI / Direct Query Interface
# ---------------------------------------------------------------------------


def execute_bi_query(lake_path: str, sql: str, params: list | None = None) -> list[dict]:
    """Execute a raw SQL query against the lake for BI tools.

    This is the DuckDB/JDBC endpoint for Looker, Metabase, or Python.
    Queries run against the full curated zone.

    SECURITY: Callers must validate/sanitize SQL before passing here.
    This function does NOT provide SQL injection protection.
    """
    from warlock.lake.query import LakeQueryEngine

    engine = LakeQueryEngine(lake_path)
    try:
        return engine.query(sql, params)
    finally:
        engine.close()


def get_available_tables(lake_path: str) -> list[dict[str, Any]]:
    """List all available lake tables with row counts for BI discovery."""
    base = Path(lake_path)
    tables: list[dict[str, Any]] = []

    for zone in ["raw", "enrichment", "curated"]:
        zone_dir = base / zone
        if not zone_dir.exists():
            continue
        for table_dir in sorted(zone_dir.rglob("*.parquet")):
            rel = str(table_dir.parent.relative_to(base))
            if rel not in [t["path"] for t in tables]:
                parquet_files = list(table_dir.parent.glob("*.parquet"))
                tables.append(
                    {
                        "zone": zone,
                        "path": rel,
                        "files": len(parquet_files),
                        "glob": str(base / rel / "*.parquet"),
                    }
                )

    return tables


# ---------------------------------------------------------------------------
# Path 3: Regulatory Filing
# ---------------------------------------------------------------------------


def generate_regulatory_filing(
    lake_path: str,
    filing_type: str,
    incident_id: str | None = None,
) -> dict[str, Any]:
    """Generate a regulatory filing document from lake data.

    Supported filing types:
    - gdpr_dpa: GDPR Data Protection Authority notification (72-hour)
    - sec_8k: SEC 8-K cybersecurity incident disclosure
    - dora_csirt: DORA CSIRT incident report
    - state_breach: US state breach notification

    Returns a dict with filing metadata and document content.
    """
    from warlock.lake.query import LakeQueryEngine

    engine = LakeQueryEngine(lake_path)
    base = Path(lake_path)
    now = datetime.now(timezone.utc)

    try:
        # Gather incident data if available
        incident_data: dict[str, Any] = {}
        incident_glob = str(base / "curated" / "incidents" / "**" / "*.parquet")
        if list(base.glob("curated/incidents/**/*.parquet")):
            if incident_id:
                results = engine.query(
                    f"""
                    SELECT * FROM read_parquet('{incident_glob}', union_by_name=true)
                    WHERE id = ?
                """,
                    [incident_id],
                )
                if results:
                    incident_data = results[0]

        # Generate filing based on type
        templates = {
            "gdpr_dpa": _gdpr_dpa_template,
            "sec_8k": _sec_8k_template,
            "dora_csirt": _dora_csirt_template,
            "state_breach": _state_breach_template,
        }

        template_fn = templates.get(filing_type)
        if not template_fn:
            return {
                "error": f"Unknown filing type: {filing_type}. Available: {list(templates.keys())}"
            }

        return template_fn(incident_data, now)
    finally:
        engine.close()


def _gdpr_dpa_template(incident: dict, now: datetime) -> dict:
    return {
        "filing_type": "gdpr_dpa",
        "title": "Personal Data Breach Notification — GDPR Article 33",
        "deadline": "72 hours from awareness",
        "generated_at": now.isoformat(),
        "sections": {
            "nature_of_breach": incident.get("classification", "To be determined"),
            "categories_affected": incident.get("data_categories", "To be determined"),
            "approximate_subjects": incident.get("affected_count", "To be determined"),
            "likely_consequences": "Assessment pending",
            "measures_taken": "Investigation in progress",
            "dpo_contact": "See system profile configuration",
        },
        "status": "draft",
    }


def _sec_8k_template(incident: dict, now: datetime) -> dict:
    return {
        "filing_type": "sec_8k",
        "title": "Form 8-K Item 1.05 — Material Cybersecurity Incident",
        "deadline": "4 business days from materiality determination",
        "generated_at": now.isoformat(),
        "sections": {
            "nature_and_scope": incident.get("classification", "To be determined"),
            "material_impact": "Assessment pending",
            "remediation_status": incident.get("status", "Investigation in progress"),
            "ongoing_risk": "Assessment pending",
        },
        "status": "draft",
    }


def _dora_csirt_template(incident: dict, now: datetime) -> dict:
    return {
        "filing_type": "dora_csirt",
        "title": "DORA Major ICT Incident Report",
        "deadline": "4 hours initial, 72 hours intermediate, 1 month final",
        "generated_at": now.isoformat(),
        "sections": {
            "incident_classification": incident.get("classification", "To be determined"),
            "affected_services": incident.get("affected_systems", "To be determined"),
            "impact_assessment": "Assessment pending",
            "recovery_timeline": "Assessment pending",
        },
        "status": "draft",
    }


def _state_breach_template(incident: dict, now: datetime) -> dict:
    return {
        "filing_type": "state_breach",
        "title": "US State Data Breach Notification",
        "deadline": "Varies by state (30-90 days typical)",
        "generated_at": now.isoformat(),
        "sections": {
            "description_of_breach": incident.get("classification", "To be determined"),
            "types_of_information": incident.get("data_categories", "To be determined"),
            "number_of_residents": incident.get("affected_count", "To be determined"),
            "steps_taken": "Investigation in progress",
            "contact_information": "See system profile configuration",
        },
        "status": "draft",
    }


# ---------------------------------------------------------------------------
# Path 4: Questionnaire Automation
# ---------------------------------------------------------------------------


def auto_fill_questionnaire(
    lake_path: str,
    questionnaire_type: str = "sig",
) -> list[dict[str, Any]]:
    """Auto-fill a security questionnaire from lake compliance data.

    Supported types:
    - sig: Shared Assessments SIG Questionnaire
    - caiq: CSA CAIQ (Consensus Assessment Initiative Questionnaire)
    - ddq: Due Diligence Questionnaire (generic)

    Returns a list of {question, answer, evidence_ref, confidence} dicts.
    """
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        summary = readers.dashboard_framework_summary()
        frameworks = readers.distinct_frameworks()
        risks = readers.top_non_compliant_risks()
    finally:
        readers.close()

    total = sum(r[2] for r in summary)
    compliant = sum(r[2] for r in summary if r[1] == "compliant")
    pct = round(compliant * 100 / total, 1) if total else 0

    # Generate answers based on questionnaire type
    if questionnaire_type == "sig":
        return _sig_answers(frameworks, pct, total, risks)
    elif questionnaire_type == "caiq":
        return _caiq_answers(frameworks, pct, total, risks)
    else:
        return _ddq_answers(frameworks, pct, total, risks)


def _sig_answers(frameworks: list, pct: float, total: int, risks: list) -> list[dict]:
    return [
        {
            "question": "A.1 - Information Security Policy",
            "answer": f"Yes — assessed across {len(frameworks)} frameworks with {pct}% compliance rate",
            "confidence": 0.9,
            "evidence_ref": "lake://curated/control_results",
        },
        {
            "question": "A.2 - Risk Assessment",
            "answer": f"Continuous — {total} control assessments, top risks: {len(risks)} non-compliant controls identified",
            "confidence": 0.85,
            "evidence_ref": "lake://curated/control_results",
        },
        {
            "question": "A.3 - Access Control",
            "answer": "Monitored via IAM connectors (Okta, AWS IAM, Entra ID)",
            "confidence": 0.8,
            "evidence_ref": "lake://enrichment",
        },
        {
            "question": "A.4 - Asset Management",
            "answer": f"Tracked via {len(frameworks)} framework controls with automated evidence collection",
            "confidence": 0.75,
            "evidence_ref": "lake://curated/control_mappings",
        },
    ]


def _caiq_answers(frameworks: list, pct: float, total: int, risks: list) -> list[dict]:
    return [
        {
            "question": "AIS-01 - Application Security",
            "answer": f"Assessed — {pct}% compliance across applicable controls",
            "confidence": 0.85,
            "evidence_ref": "lake://curated/control_results",
        },
        {
            "question": "BCR-01 - Business Continuity Planning",
            "answer": "Evidence collected via pipeline connectors",
            "confidence": 0.7,
            "evidence_ref": "lake://enrichment",
        },
        {
            "question": "CCC-01 - Change Control",
            "answer": f"Monitored across {len(frameworks)} frameworks",
            "confidence": 0.8,
            "evidence_ref": "lake://curated/control_mappings",
        },
    ]


def _ddq_answers(frameworks: list, pct: float, total: int, risks: list) -> list[dict]:
    return [
        {
            "question": "Do you have an information security program?",
            "answer": f"Yes — {len(frameworks)} compliance frameworks monitored continuously with {total} automated control assessments",
            "confidence": 0.95,
            "evidence_ref": "lake://curated/agg_framework_posture",
        },
        {
            "question": "How do you manage vulnerabilities?",
            "answer": f"Automated scanning via pipeline connectors. {len(risks)} non-compliant controls currently tracked for remediation.",
            "confidence": 0.85,
            "evidence_ref": "lake://curated/control_results",
        },
        {
            "question": "Do you have incident response procedures?",
            "answer": "Yes — incident lifecycle tracked from detection through closure with regulatory notification support",
            "confidence": 0.7,
            "evidence_ref": "lake://curated/incidents",
        },
    ]


# ---------------------------------------------------------------------------
# Path 5: Trust Center
# ---------------------------------------------------------------------------


def generate_trust_center_data(lake_path: str) -> dict[str, Any]:
    """Generate data for a customer-facing trust center portal.

    Returns:
    - posture_badges: per-framework compliance badges (compliant/partial/non-compliant)
    - artifacts: list of available compliance artifacts
    - last_updated: timestamp of latest assessment
    """
    from warlock.lake.readers import LakeReaders

    readers = LakeReaders(lake_path)
    try:
        summary = readers.dashboard_framework_summary()
        frameworks = readers.distinct_frameworks()
        last = readers.last_assessed_at()
    finally:
        readers.close()

    # Compute per-framework badges
    badges: dict[str, dict[str, Any]] = {}
    for fw in frameworks:
        fw_results = [r for r in summary if r[0] == fw]
        total = sum(r[2] for r in fw_results)
        compliant = sum(r[2] for r in fw_results if r[1] == "compliant")
        pct = round(compliant * 100 / total, 1) if total else 0

        if pct >= 90:
            badge = "compliant"
        elif pct >= 50:
            badge = "partial"
        else:
            badge = "needs_attention"

        badges[fw] = {
            "status": badge,
            "compliance_pct": pct,
            "total_controls": total,
            "compliant_controls": compliant,
        }

    artifacts = [
        {"name": "SOC 2 Type II Report", "available": "soc2" in frameworks, "format": "PDF"},
        {
            "name": "ISO 27001 Statement of Applicability",
            "available": "iso_27001" in frameworks,
            "format": "PDF",
        },
        {
            "name": "NIST 800-53 SSP",
            "available": "nist_800_53" in frameworks,
            "format": "OSCAL/JSON",
        },
        {"name": "Penetration Test Summary", "available": False, "format": "PDF"},
        {"name": "SIG Questionnaire (Pre-filled)", "available": True, "format": "XLSX"},
    ]

    return {
        "posture_badges": badges,
        "artifacts": artifacts,
        "last_updated": str(last) if last else None,
        "framework_count": len(frameworks),
    }
