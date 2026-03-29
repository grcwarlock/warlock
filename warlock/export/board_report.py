"""Board-level compliance report generation for Warlock GRC platform.

Produces a PDF-ready Markdown report summarising compliance posture,
key risk indicators (KRIs), POA&M status, and trend data suitable for
board of directors or executive leadership review.

Uses ReportLab (optional) for direct PDF output.  When ReportLab is
unavailable, generates Markdown that can be converted externally.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import ControlResult, Finding, Issue

log = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False


# ---------------------------------------------------------------------------
# Data aggregation
# ---------------------------------------------------------------------------


def _gather_board_data(session: Session) -> dict[str, Any]:
    """Query the database and aggregate board-level metrics.

    Returns a dict with keys:
        - frameworks: list of per-framework posture dicts
        - kris: key risk indicators
        - poam_summary: POA&M status counts
        - findings_summary: finding severity breakdown
        - generated_at: ISO timestamp
    """
    from warlock.db.models import POAM

    all_results: list[ControlResult] = session.query(ControlResult).all()
    all_findings: list[Finding] = session.query(Finding).all()

    # Attempt to load POAMs (table may not exist in all envs)
    try:
        all_poams: list[POAM] = session.query(POAM).all()
    except Exception:
        all_poams = []

    # Per-framework posture
    by_framework: dict[str, list[ControlResult]] = {}
    for cr in all_results:
        by_framework.setdefault(cr.framework, []).append(cr)

    frameworks: list[dict[str, Any]] = []
    for fw, crs in sorted(by_framework.items()):
        statuses = Counter(cr.status for cr in crs)
        total = len(crs)
        compliant = statuses.get("compliant", 0)
        pct = round(100 * compliant / total, 1) if total else 0.0
        frameworks.append(
            {
                "framework": fw,
                "total_controls": total,
                "compliant": compliant,
                "non_compliant": statuses.get("non_compliant", 0),
                "partial": statuses.get("partial", 0),
                "not_assessed": statuses.get("not_assessed", 0),
                "compliance_pct": pct,
            }
        )

    # KRIs
    total_controls = len(all_results)
    total_compliant = sum(1 for cr in all_results if cr.status == "compliant")
    total_non_compliant = sum(1 for cr in all_results if cr.status == "non_compliant")
    overall_pct = round(100 * total_compliant / total_controls, 1) if total_controls else 0.0

    severity_counts = Counter((f.severity or "unknown").lower() for f in all_findings)
    critical_high = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

    open_issues = 0
    try:
        open_issues = (
            session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
        )
    except Exception:
        pass

    kris: dict[str, Any] = {
        "overall_compliance_pct": overall_pct,
        "total_controls_assessed": total_controls,
        "total_compliant": total_compliant,
        "total_non_compliant": total_non_compliant,
        "critical_high_findings": critical_high,
        "total_findings": len(all_findings),
        "open_issues": open_issues,
        "frameworks_assessed": len(frameworks),
    }

    # POA&M summary
    poam_statuses = Counter(p.status for p in all_poams)
    poam_summary: dict[str, int] = dict(poam_statuses)
    poam_summary["total"] = len(all_poams)

    # Finding severity breakdown
    findings_summary: dict[str, int] = dict(severity_counts)
    findings_summary["total"] = len(all_findings)

    return {
        "frameworks": frameworks,
        "kris": kris,
        "poam_summary": poam_summary,
        "findings_summary": findings_summary,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def generate_board_markdown(session: Session) -> str:
    """Generate a board-level compliance report as Markdown.

    Args:
        session: SQLAlchemy session.

    Returns:
        Markdown string.
    """
    data = _gather_board_data(session)
    kris = data["kris"]
    lines: list[str] = []

    lines.append("# Board Compliance Report")
    lines.append("")
    lines.append(f"**Generated:** {data['generated_at']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"Warlock GRC assessed **{kris['total_controls_assessed']:,}** "
        f"controls across **{kris['frameworks_assessed']}** frameworks. "
        f"Overall compliance stands at **{kris['overall_compliance_pct']}%**."
    )
    lines.append("")
    if kris["critical_high_findings"] > 0:
        lines.append(
            f"There are **{kris['critical_high_findings']}** "
            "critical/high-severity findings requiring immediate attention."
        )
        lines.append("")

    # KRIs table
    lines.append("## Key Risk Indicators")
    lines.append("")
    lines.append("| Indicator | Value |")
    lines.append("|---|---|")
    lines.append(f"| Overall Compliance | {kris['overall_compliance_pct']}% |")
    lines.append(f"| Controls Assessed | {kris['total_controls_assessed']:,} |")
    lines.append(f"| Controls Compliant | {kris['total_compliant']:,} |")
    lines.append(f"| Controls Non-Compliant | {kris['total_non_compliant']:,} |")
    lines.append(f"| Critical/High Findings | {kris['critical_high_findings']:,} |")
    lines.append(f"| Total Findings | {kris['total_findings']:,} |")
    lines.append(f"| Open Issues | {kris['open_issues']:,} |")
    lines.append("")

    # Framework Posture
    lines.append("## Compliance Posture by Framework")
    lines.append("")
    lines.append("| Framework | Controls | Compliant | Non-Compliant | Partial | Compliance % |")
    lines.append("|---|---|---|---|---|---|")
    for fw in data["frameworks"]:
        lines.append(
            f"| {fw['framework']} | {fw['total_controls']:,} "
            f"| {fw['compliant']:,} | {fw['non_compliant']:,} "
            f"| {fw['partial']:,} | {fw['compliance_pct']}% |"
        )
    lines.append("")

    # POA&M Summary
    poam = data["poam_summary"]
    if poam.get("total", 0) > 0:
        lines.append("## POA&M Status")
        lines.append("")
        lines.append("| Status | Count |")
        lines.append("|---|---|")
        for status, count in sorted(poam.items()):
            if status != "total":
                lines.append(f"| {status.replace('_', ' ').title()} | {count} |")
        lines.append(f"| **Total** | **{poam['total']}** |")
        lines.append("")

    # Findings by Severity
    findings = data["findings_summary"]
    if findings.get("total", 0) > 0:
        lines.append("## Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        severity_order = [
            "critical",
            "high",
            "medium",
            "moderate",
            "low",
            "info",
        ]
        for sev in severity_order:
            if sev in findings:
                lines.append(f"| {sev.title()} | {findings[sev]:,} |")
        # Any other severities
        for sev, count in sorted(findings.items()):
            if sev not in severity_order and sev != "total":
                lines.append(f"| {sev.title()} | {count:,} |")
        lines.append(f"| **Total** | **{findings['total']:,}** |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Generated by Warlock GRC Platform. For internal use only.*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PDF rendering (optional)
# ---------------------------------------------------------------------------


def generate_board_pdf(session: Session, output_path: str) -> str:
    """Generate a board-level PDF compliance report.

    If ReportLab is available, produces a formatted PDF directly.
    Otherwise, writes Markdown to ``output_path`` (with ``.md`` extension).

    Args:
        session: SQLAlchemy session.
        output_path: Destination file path.

    Returns:
        Path to the written file.
    """
    if not _HAS_REPORTLAB:
        log.warning("ReportLab not installed; generating Markdown instead of PDF")
        md_path = output_path.replace(".pdf", ".md")
        md_content = generate_board_markdown(session)
        from pathlib import Path

        dest = Path(md_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(md_content, encoding="utf-8")
        return str(dest)

    data = _gather_board_data(session)
    kris = data["kris"]

    from pathlib import Path

    dest = Path(output_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(dest),
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "BoardTitle",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=20,
    )
    heading_style = ParagraphStyle(
        "BoardHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceAfter=10,
        spaceBefore=16,
    )

    elements: list[Any] = []

    # Title
    elements.append(Paragraph("Board Compliance Report", title_style))
    elements.append(
        Paragraph(
            f"Generated: {data['generated_at']}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 20))

    # Executive Summary
    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(
        Paragraph(
            f"Warlock GRC assessed {kris['total_controls_assessed']:,} "
            f"controls across {kris['frameworks_assessed']} frameworks. "
            f"Overall compliance: {kris['overall_compliance_pct']}%.",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 12))

    # KRI table
    elements.append(Paragraph("Key Risk Indicators", heading_style))
    kri_data = [
        ["Indicator", "Value"],
        ["Overall Compliance", f"{kris['overall_compliance_pct']}%"],
        ["Controls Assessed", f"{kris['total_controls_assessed']:,}"],
        ["Controls Compliant", f"{kris['total_compliant']:,}"],
        ["Controls Non-Compliant", f"{kris['total_non_compliant']:,}"],
        [
            "Critical/High Findings",
            f"{kris['critical_high_findings']:,}",
        ],
        ["Total Findings", f"{kris['total_findings']:,}"],
        ["Open Issues", f"{kris['open_issues']:,}"],
    ]
    kri_table = Table(kri_data, colWidths=[3 * inch, 2 * inch])
    kri_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ]
        )
    )
    elements.append(kri_table)
    elements.append(Spacer(1, 16))

    # Framework posture table
    elements.append(Paragraph("Compliance Posture by Framework", heading_style))
    fw_data = [
        [
            "Framework",
            "Controls",
            "Compliant",
            "Non-Compl.",
            "Partial",
            "%",
        ]
    ]
    for fw in data["frameworks"]:
        fw_data.append(
            [
                fw["framework"],
                str(fw["total_controls"]),
                str(fw["compliant"]),
                str(fw["non_compliant"]),
                str(fw["partial"]),
                f"{fw['compliance_pct']}%",
            ]
        )
    fw_table = Table(
        fw_data,
        colWidths=[
            1.8 * inch,
            0.8 * inch,
            0.9 * inch,
            0.9 * inch,
            0.7 * inch,
            0.6 * inch,
        ],
    )
    fw_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
            ]
        )
    )
    elements.append(fw_table)
    elements.append(Spacer(1, 16))

    # Footer
    elements.append(
        Paragraph(
            "<i>Generated by Warlock GRC Platform. For internal use only.</i>",
            styles["Normal"],
        )
    )

    doc.build(elements)
    log.info("Board report PDF written to %s", dest)
    return str(dest)
