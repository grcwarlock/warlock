"""PDF report generation for Warlock GRC platform.

Uses ReportLab (optional dependency) to produce compliance, POA&M,
and executive summary reports.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from warlock.utils import ensure_aware

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
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


def _require_reportlab() -> None:
    if not _HAS_REPORTLAB:
        raise RuntimeError(
            "reportlab is required for PDF generation. Install it with: pip install reportlab"
        )


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _build_table(headers: list[str], rows: list[list[str]]) -> "Table":
    """Build a styled ReportLab table."""
    data = [headers] + rows
    t = Table(data, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ecf0f1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ecf0f1")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return t


# ---------------------------------------------------------------------------
# Compliance PDF
# ---------------------------------------------------------------------------


def generate_compliance_pdf(
    session: "Session",
    framework: str | None = None,
    output_path: str | None = None,
) -> str:
    """Generate a compliance summary PDF.

    Args:
        session: SQLAlchemy session.
        framework: Optional framework filter.
        output_path: Output file path. Auto-generated if None.

    Returns:
        Path to the generated PDF file.
    """
    _require_reportlab()

    from warlock.db.models import ControlResult

    q = session.query(ControlResult)
    if framework:
        q = q.filter(ControlResult.framework == framework)
    results = q.all()

    if not output_path:
        suffix = f"-{framework}" if framework else ""
        output_path = f"compliance-report{suffix}-{datetime.now(timezone.utc):%Y%m%d}.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements: list = []

    # Title
    title = f"Compliance Report — {framework or 'All Frameworks'}"
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Paragraph(f"Generated: {_now_str()}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Summary stats
    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    partial = sum(1 for r in results if r.status == "partial")
    not_assessed = sum(1 for r in results if r.status == "not_assessed")
    score = (compliant / total * 100) if total else 0.0

    summary_text = (
        f"Posture Score: {score:.1f}%  |  "
        f"Total Controls: {total}  |  "
        f"Compliant: {compliant}  |  "
        f"Non-Compliant: {non_compliant}  |  "
        f"Partial: {partial}  |  "
        f"Not Assessed: {not_assessed}"
    )
    elements.append(Paragraph(summary_text, styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Per-framework breakdown
    frameworks: dict[str, list] = {}
    for r in results:
        frameworks.setdefault(r.framework, []).append(r)

    for fw, fw_results in sorted(frameworks.items()):
        elements.append(Paragraph(f"Framework: {fw}", styles["Heading2"]))
        rows = []
        for r in fw_results[:200]:  # Cap rows for readability
            rows.append(
                [
                    r.control_id,
                    r.status,
                    getattr(r, "evidence_summary", "") or "",
                ]
            )
        if rows:
            t = _build_table(["Control ID", "Status", "Evidence Summary"], rows)
            elements.append(t)
            elements.append(Spacer(1, 0.2 * inch))

    doc.build(elements)
    log.info("Compliance PDF generated: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# POA&M PDF
# ---------------------------------------------------------------------------


def generate_poam_pdf(
    session: "Session",
    framework: str | None = None,
    output_path: str | None = None,
) -> str:
    """Generate a POA&M report PDF.

    Args:
        session: SQLAlchemy session.
        framework: Optional framework filter.
        output_path: Output file path. Auto-generated if None.

    Returns:
        Path to the generated PDF file.
    """
    _require_reportlab()

    from warlock.db.models import POAM

    q = session.query(POAM)
    if framework:
        q = q.filter(POAM.framework == framework)
    poams = q.all()

    if not output_path:
        suffix = f"-{framework}" if framework else ""
        output_path = f"poam-report{suffix}-{datetime.now(timezone.utc):%Y%m%d}.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements: list = []

    title = f"Plan of Action & Milestones — {framework or 'All Frameworks'}"
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Paragraph(f"Generated: {_now_str()}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    total = len(poams)
    open_count = sum(1 for p in poams if p.status in ("open", "in_progress", "draft"))
    elements.append(
        Paragraph(f"Total POA&M Items: {total}  |  Open: {open_count}", styles["Normal"])
    )
    elements.append(Spacer(1, 0.3 * inch))

    rows = []
    for p in poams[:300]:
        scheduled = getattr(p, "scheduled_completion", None)
        due = ""
        if scheduled:
            scheduled = ensure_aware(scheduled)
            due = scheduled.strftime("%Y-%m-%d")
        rows.append(
            [
                p.framework,
                p.control_id,
                p.severity,
                p.status,
                (p.weakness_description or "")[:80],
                due,
            ]
        )

    if rows:
        t = _build_table(
            ["Framework", "Control", "Severity", "Status", "Weakness", "Due Date"],
            rows,
        )
        elements.append(t)
    else:
        elements.append(Paragraph("No POA&M items found.", styles["Normal"]))

    doc.build(elements)
    log.info("POA&M PDF generated: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Executive Summary PDF
# ---------------------------------------------------------------------------


def generate_executive_pdf(
    session: "Session",
    output_path: str | None = None,
) -> str:
    """Generate an executive summary PDF.

    Args:
        session: SQLAlchemy session.
        output_path: Output file path. Auto-generated if None.

    Returns:
        Path to the generated PDF file.
    """
    _require_reportlab()

    from warlock.db.models import ControlResult, Finding, Issue, POAM

    if not output_path:
        output_path = f"executive-summary-{datetime.now(timezone.utc):%Y%m%d}.pdf"

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements: list = []

    elements.append(Paragraph("Executive Summary — Warlock GRC", styles["Title"]))
    elements.append(Paragraph(f"Generated: {_now_str()}", styles["Normal"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Overall posture
    total_results = session.query(ControlResult).count()
    compliant = session.query(ControlResult).filter(ControlResult.status == "compliant").count()
    score = (compliant / total_results * 100) if total_results else 0.0

    total_findings = session.query(Finding).count()
    open_issues = session.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
    open_poams = (
        session.query(POAM).filter(POAM.status.in_(["open", "in_progress", "draft"])).count()
    )

    elements.append(Paragraph("Overall Posture", styles["Heading2"]))
    summary_rows = [
        ["Posture Score", f"{score:.1f}%"],
        ["Total Control Assessments", str(total_results)],
        ["Compliant Controls", str(compliant)],
        ["Total Findings", str(total_findings)],
        ["Open Issues", str(open_issues)],
        ["Open POA&M Items", str(open_poams)],
    ]
    t = _build_table(["Metric", "Value"], summary_rows)
    elements.append(t)
    elements.append(Spacer(1, 0.3 * inch))

    # Per-framework breakdown
    elements.append(Paragraph("Framework Breakdown", styles["Heading2"]))
    fw_rows = []
    frameworks = (
        session.query(ControlResult.framework).distinct().order_by(ControlResult.framework).all()
    )
    for (fw,) in frameworks:
        fw_total = session.query(ControlResult).filter(ControlResult.framework == fw).count()
        fw_compliant = (
            session.query(ControlResult)
            .filter(ControlResult.framework == fw, ControlResult.status == "compliant")
            .count()
        )
        fw_score = (fw_compliant / fw_total * 100) if fw_total else 0.0
        fw_rows.append([fw, str(fw_total), str(fw_compliant), f"{fw_score:.1f}%"])

    if fw_rows:
        t = _build_table(["Framework", "Total", "Compliant", "Score"], fw_rows)
        elements.append(t)

    doc.build(elements)
    log.info("Executive PDF generated: %s", output_path)
    return output_path
