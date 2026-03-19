"""Framework-specific report generation.

Generates structured reports in the format auditors expect:
- SOC 2 Type II: Management assertion, service description, control descriptions, test results, exceptions
- ISO 27001: Statement of Applicability (SoA) with implementation status per Annex A control
- Generic: Markdown/HTML report for any framework
"""

from __future__ import annotations

import html as _html
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import distinct
from sqlalchemy.orm import Session

from warlock.db.models import (
    AuditEngagement,
    ControlMapping,
    ControlResult,
    Finding,
)
from warlock.assessors.posture import PostureAggregator

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_engagement(session: Session, engagement_id: str) -> AuditEngagement:
    """Load an AuditEngagement or raise."""
    eng = (
        session.query(AuditEngagement)
        .filter(AuditEngagement.id == engagement_id)
        .first()
    )
    if not eng:
        raise ValueError(f"Engagement not found: {engagement_id}")
    return eng


def _iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _query_results_for_engagement(
    session: Session,
    framework: str,
    period_start: datetime,
    period_end: datetime,
    in_scope: list[str] | None = None,
    excluded: list[str] | None = None,
) -> list[ControlResult]:
    """Query ControlResults within an engagement period."""
    query = (
        session.query(ControlResult)
        .filter(
            ControlResult.framework == framework,
            ControlResult.assessed_at >= period_start,
            ControlResult.assessed_at <= period_end,
        )
    )
    if in_scope:
        query = query.filter(ControlResult.control_id.in_(in_scope))
    if excluded:
        query = query.filter(~ControlResult.control_id.in_(excluded))
    return query.all()


def _group_by_control(results: list[ControlResult]) -> dict[str, list[ControlResult]]:
    """Group ControlResults by control_id."""
    grouped: dict[str, list[ControlResult]] = {}
    for r in results:
        grouped.setdefault(r.control_id, []).append(r)
    return grouped


def _aggregate_status(results: list[ControlResult]) -> str:
    """Worst-case status rollup for a set of results."""
    statuses = {r.status for r in results}
    if "non_compliant" in statuses:
        return "non_compliant"
    if "partial" in statuses:
        return "partial"
    if "compliant" in statuses:
        return "compliant"
    return "not_assessed"


def _get_narrator():
    """Try to get an AINarrator, return None if not available."""
    try:
        from warlock.assessors.ai_narrator import create_narrator
        return create_narrator()
    except Exception:
        return None


def _generate_narrative(narrator: Any, session: Session, framework: str, control_id: str) -> str | None:
    """Generate an AI narrative for a control, or return None."""
    if narrator is None:
        return None
    try:
        from warlock.assessors.ai_narrator import aggregate_control_evidence
        evidence = aggregate_control_evidence(session, framework, control_id)
        if not evidence.findings:
            return None
        impl = narrator.generate_implementation(evidence)
        return impl.narrative if impl.narrative else None
    except Exception:
        log.debug("AI narrative generation failed for %s/%s", framework, control_id)
        return None


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates framework-specific compliance reports."""

    def generate_soc2_report(
        self,
        session: Session,
        engagement_id: str,
    ) -> dict[str, Any]:
        """Produce a SOC 2 Type II report structure.

        Args:
            session: SQLAlchemy session.
            engagement_id: ID of the AuditEngagement.

        Returns:
            Dict conforming to SOC 2 Type II report structure.
        """
        eng = _get_engagement(session, engagement_id)
        results = _query_results_for_engagement(
            session, eng.framework, eng.period_start, eng.period_end,
            in_scope=eng.in_scope_controls or None,
            excluded=eng.excluded_controls or None,
        )
        by_control = _group_by_control(results)

        narrator = _get_narrator()

        # Build per-criteria descriptions
        control_descriptions: list[dict[str, Any]] = []
        with_exceptions = 0
        no_exceptions = 0

        for control_id in sorted(by_control.keys()):
            crs = by_control[control_id]
            agg_status = _aggregate_status(crs)

            # Exceptions: non-compliant findings
            exceptions: list[dict[str, Any]] = []
            for r in crs:
                if r.status == "non_compliant":
                    exceptions.append({
                        "finding_id": r.finding_id,
                        "severity": r.severity,
                        "assertion": r.assertion_name or "",
                        "detail": (
                            r.assertion_findings[:3]
                            if r.assertion_findings
                            else [r.ai_assessment[:200] if r.ai_assessment else "Non-compliant"]
                        ),
                        "remediation": r.remediation_summary or "",
                    })

            if exceptions:
                with_exceptions += 1
            else:
                no_exceptions += 1

            # Test procedure / result narrative
            test_procedure = self._soc2_test_procedure(crs)
            test_result = self._soc2_test_result(crs, agg_status)

            # AI narrative for description if available
            description = _generate_narrative(narrator, session, eng.framework, control_id)
            if not description:
                description = self._soc2_control_description(crs, agg_status)

            control_descriptions.append({
                "criteria": control_id,
                "description": description,
                "test_procedure": test_procedure,
                "test_result": test_result,
                "status": agg_status,
                "exceptions": exceptions,
            })

        # Management assertion
        total_criteria = len(by_control)
        management_assertion = (
            f"Management of the service organization asserts that the controls "
            f"within the system were suitably designed and operating effectively "
            f"to provide reasonable assurance that the applicable trust services "
            f"criteria were met throughout the period "
            f"{eng.period_start.strftime('%B %d, %Y')} to "
            f"{eng.period_end.strftime('%B %d, %Y')}."
        )
        if with_exceptions > 0:
            management_assertion += (
                f" Exceptions were noted in {with_exceptions} of "
                f"{total_criteria} criteria evaluated."
            )

        # Service description
        sources = set()
        for crs in by_control.values():
            for r in crs:
                if r.assessor:
                    sources.add(r.assessor.split(":")[0])
        service_description = (
            f"The service organization's system was evaluated using automated "
            f"and deterministic controls assessment. Evidence was collected from "
            f"{len(sources)} assessment source(s) covering {total_criteria} "
            f"trust services criteria over the audit period."
        )

        return {
            "report_type": "SOC 2 Type II",
            "engagement_id": engagement_id,
            "engagement_name": eng.name,
            "period": {
                "start": _iso(eng.period_start),
                "end": _iso(eng.period_end),
            },
            "auditor": {
                "name": eng.auditor_name or "",
                "firm": eng.auditor_firm or "",
            },
            "management_assertion": management_assertion,
            "service_description": service_description,
            "control_descriptions": control_descriptions,
            "summary": {
                "total_criteria": total_criteria,
                "with_exceptions": with_exceptions,
                "no_exceptions": no_exceptions,
            },
            "generated_at": _iso(datetime.now(timezone.utc)),
        }

    def generate_iso_soa(
        self,
        session: Session,
        engagement_id: str,
    ) -> dict[str, Any]:
        """Produce an ISO 27001:2022 Statement of Applicability.

        Args:
            session: SQLAlchemy session.
            engagement_id: ID of the AuditEngagement.

        Returns:
            Dict conforming to ISO 27001 SoA structure.
        """
        eng = _get_engagement(session, engagement_id)
        results = _query_results_for_engagement(
            session, eng.framework, eng.period_start, eng.period_end,
            in_scope=eng.in_scope_controls or None,
            excluded=eng.excluded_controls or None,
        )
        by_control = _group_by_control(results)

        narrator = _get_narrator()

        # Also get excluded controls for "not applicable" entries
        excluded = eng.excluded_controls or []

        controls: list[dict[str, Any]] = []

        # Controls with evidence
        for control_id in sorted(by_control.keys()):
            crs = by_control[control_id]
            agg_status = _aggregate_status(crs)

            # Map to ISO implementation status
            impl_status = {
                "compliant": "implemented",
                "partial": "partially_implemented",
                "non_compliant": "not_implemented",
                "not_assessed": "planned",
            }.get(agg_status, "planned")

            # Justification
            justification = self._iso_justification(crs, agg_status)

            # Evidence summary
            evidence_summary = _generate_narrative(narrator, session, eng.framework, control_id)
            if not evidence_summary:
                evidence_summary = self._iso_evidence_summary(crs)

            controls.append({
                "control_id": control_id,
                "applicable": True,
                "justification": justification,
                "implementation_status": impl_status,
                "evidence_summary": evidence_summary,
                "finding_count": len(crs),
                "compliant_count": sum(1 for r in crs if r.status == "compliant"),
                "non_compliant_count": sum(1 for r in crs if r.status == "non_compliant"),
            })

        # Excluded controls marked not applicable
        for control_id in sorted(excluded):
            controls.append({
                "control_id": control_id,
                "applicable": False,
                "justification": "Excluded from scope for this engagement.",
                "implementation_status": "not_applicable",
                "evidence_summary": "",
                "finding_count": 0,
                "compliant_count": 0,
                "non_compliant_count": 0,
            })

        return {
            "report_type": "ISO 27001:2022 Statement of Applicability",
            "engagement_id": engagement_id,
            "engagement_name": eng.name,
            "period": {
                "start": _iso(eng.period_start),
                "end": _iso(eng.period_end),
            },
            "auditor": {
                "name": eng.auditor_name or "",
                "firm": eng.auditor_firm or "",
            },
            "controls": controls,
            "summary": {
                "total_controls": len(controls),
                "applicable": sum(1 for c in controls if c["applicable"]),
                "not_applicable": sum(1 for c in controls if not c["applicable"]),
                "implemented": sum(
                    1 for c in controls
                    if c["implementation_status"] == "implemented"
                ),
                "partially_implemented": sum(
                    1 for c in controls
                    if c["implementation_status"] == "partially_implemented"
                ),
                "not_implemented": sum(
                    1 for c in controls
                    if c["implementation_status"] == "not_implemented"
                ),
                "planned": sum(
                    1 for c in controls
                    if c["implementation_status"] == "planned"
                ),
            },
            "generated_at": _iso(datetime.now(timezone.utc)),
        }

    def generate_markdown(
        self,
        session: Session,
        framework: str,
        engagement_id: str | None = None,
    ) -> str:
        """Generate a generic markdown compliance report.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            engagement_id: Optional engagement to scope by period.

        Returns:
            Markdown string.
        """
        now = datetime.now(timezone.utc)

        # Determine scope
        if engagement_id:
            eng = _get_engagement(session, engagement_id)
            results = _query_results_for_engagement(
                session, eng.framework, eng.period_start, eng.period_end,
                in_scope=eng.in_scope_controls or None,
                excluded=eng.excluded_controls or None,
            )
            period_text = (
                f"{eng.period_start.strftime('%Y-%m-%d')} to "
                f"{eng.period_end.strftime('%Y-%m-%d')}"
            )
            title = f"{eng.name} - Compliance Report"
        else:
            results = (
                session.query(ControlResult)
                .filter(ControlResult.framework == framework)
                .all()
            )
            period_text = f"As of {now.strftime('%Y-%m-%d %H:%M UTC')}"
            title = f"{framework} Compliance Report"

        by_control = _group_by_control(results)
        aggregator = PostureAggregator()

        lines: list[str] = []
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**Framework:** {framework}  ")
        lines.append(f"**Period:** {period_text}  ")
        lines.append(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M UTC')}  ")
        lines.append("")

        # Summary
        total = len(by_control)
        compliant_controls = 0
        non_compliant_controls = 0
        partial_controls = 0

        for crs in by_control.values():
            status = _aggregate_status(crs)
            if status == "compliant":
                compliant_controls += 1
            elif status == "non_compliant":
                non_compliant_controls += 1
            elif status == "partial":
                partial_controls += 1

        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Metric | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Controls | {total} |")
        lines.append(f"| Compliant | {compliant_controls} |")
        lines.append(f"| Non-Compliant | {non_compliant_controls} |")
        lines.append(f"| Partial | {partial_controls} |")
        lines.append(f"| Total Findings | {len(results)} |")
        lines.append("")

        # Per-control details
        lines.append("## Control Details")
        lines.append("")

        for control_id in sorted(by_control.keys()):
            crs = by_control[control_id]
            agg_status = _aggregate_status(crs)
            status_icon = {
                "compliant": "PASS",
                "non_compliant": "FAIL",
                "partial": "PARTIAL",
                "not_assessed": "N/A",
            }.get(agg_status, "?")

            lines.append(f"### {control_id} [{status_icon}]")
            lines.append("")

            compliant = sum(1 for r in crs if r.status == "compliant")
            non_compliant = sum(1 for r in crs if r.status == "non_compliant")
            partial = sum(1 for r in crs if r.status == "partial")

            lines.append(
                f"**Findings:** {len(crs)} total "
                f"({compliant} compliant, {non_compliant} non-compliant, "
                f"{partial} partial)"
            )
            lines.append("")

            # List non-compliant findings
            failures = [r for r in crs if r.status == "non_compliant"]
            if failures:
                lines.append("**Exceptions:**")
                lines.append("")
                for f in failures[:10]:
                    detail = ""
                    if f.assertion_findings:
                        detail = "; ".join(
                            str(x) for x in f.assertion_findings[:3]
                        )
                    elif f.ai_assessment:
                        detail = f.ai_assessment[:150]
                    lines.append(f"- [{f.severity}] {detail or 'Non-compliant finding'}")
                if len(failures) > 10:
                    lines.append(f"- ... and {len(failures) - 10} more")
                lines.append("")

            # Remediation
            remediations = [
                r.remediation_summary
                for r in crs
                if r.remediation_summary and r.status == "non_compliant"
            ]
            if remediations:
                lines.append("**Remediation:**")
                lines.append("")
                seen: set[str] = set()
                for rem in remediations:
                    if rem not in seen:
                        seen.add(rem)
                        lines.append(f"- {rem}")
                lines.append("")

        return "\n".join(lines)

    def generate_html(
        self,
        session: Session,
        framework: str,
        engagement_id: str | None = None,
    ) -> str:
        """Generate an HTML compliance report.

        Wraps the markdown report in a styled HTML document suitable
        for browser viewing or PDF conversion.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            engagement_id: Optional engagement to scope by period.

        Returns:
            HTML string.
        """
        md_content = self.generate_markdown(session, framework, engagement_id)

        # Convert markdown to HTML (basic conversion)
        html_body = self._markdown_to_html(md_content)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{framework} Compliance Report</title>
<style>
  @media print {{
    body {{ font-size: 11pt; }}
    .no-print {{ display: none; }}
    h1, h2, h3 {{ page-break-after: avoid; }}
    table {{ page-break-inside: avoid; }}
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    line-height: 1.6;
    color: #1a1a1a;
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem;
    background: #fff;
  }}
  h1 {{
    color: #1a1a1a;
    border-bottom: 2px solid #333;
    padding-bottom: 0.5rem;
  }}
  h2 {{
    color: #2c3e50;
    border-bottom: 1px solid #ddd;
    padding-bottom: 0.3rem;
    margin-top: 2rem;
  }}
  h3 {{
    color: #34495e;
    margin-top: 1.5rem;
  }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 1rem 0;
  }}
  th, td {{
    border: 1px solid #ddd;
    padding: 0.5rem 0.75rem;
    text-align: left;
  }}
  th {{
    background: #f5f5f5;
    font-weight: 600;
  }}
  tr:nth-child(even) {{
    background: #fafafa;
  }}
  ul {{
    padding-left: 1.5rem;
  }}
  li {{
    margin-bottom: 0.3rem;
  }}
  code {{
    background: #f4f4f4;
    padding: 0.15rem 0.3rem;
    border-radius: 3px;
    font-size: 0.9em;
  }}
  .pass {{ color: #27ae60; font-weight: bold; }}
  .fail {{ color: #e74c3c; font-weight: bold; }}
  .partial {{ color: #f39c12; font-weight: bold; }}
  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid #ddd;
    color: #888;
    font-size: 0.85rem;
  }}
</style>
</head>
<body>
{html_body}
<footer>
  Generated by Warlock GRC Platform | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</footer>
</body>
</html>"""

    def generate_pdf(
        self,
        session: Session,
        framework: str,
        engagement_id: str | None = None,
    ) -> bytes:
        """Generate a PDF compliance report.

        Attempts to use weasyprint for high-quality PDF generation.
        Falls back to a basic HTML-with-print-CSS approach if weasyprint
        is not installed.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            engagement_id: Optional engagement to scope by period.

        Returns:
            PDF bytes.

        Raises:
            ImportError: If no PDF generation library is available.
        """
        html_content = self.generate_html(session, framework, engagement_id)

        # Try weasyprint first
        try:
            import weasyprint
            pdf_doc = weasyprint.HTML(string=html_content).write_pdf()
            log.info("PDF generated via weasyprint (%d bytes)", len(pdf_doc))
            return pdf_doc
        except ImportError:
            pass

        # If weasyprint is not available, raise with helpful message
        raise ImportError(
            "PDF generation requires the 'weasyprint' package. "
            "Install it with: pip install weasyprint\n"
            "Note: weasyprint requires system dependencies (cairo, pango, etc.). "
            "See https://doc.courtbouillon.org/weasyprint/stable/first_steps.html\n"
            "As an alternative, you can use generate_html() and convert to PDF "
            "using your browser's print-to-PDF feature (the HTML includes print CSS)."
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _soc2_test_procedure(results: list[ControlResult]) -> str:
        """Generate a test procedure description from control results."""
        methods: set[str] = set()
        for r in results:
            if r.assertion_name:
                methods.add(f"automated assertion ({r.assertion_name})")
            elif r.ai_assessment:
                methods.add("AI-assisted evaluation")
            else:
                methods.add("evidence review")

        return (
            f"Warlock GRC performed automated testing using: "
            f"{', '.join(sorted(methods))}. "
            f"{len(results)} finding(s) were evaluated across the audit period."
        )

    @staticmethod
    def _soc2_test_result(results: list[ControlResult], status: str) -> str:
        """Generate a test result description."""
        compliant = sum(1 for r in results if r.status == "compliant")
        non_compliant = sum(1 for r in results if r.status == "non_compliant")

        if status == "compliant":
            return (
                f"No exceptions noted. All {compliant} finding(s) demonstrate "
                f"the control was operating effectively throughout the period."
            )
        elif status == "non_compliant":
            return (
                f"Exceptions noted. {non_compliant} of {len(results)} finding(s) "
                f"indicate the control was not operating effectively."
            )
        elif status == "partial":
            return (
                f"Partial exceptions noted. {compliant} of {len(results)} "
                f"finding(s) indicate effective operation; {non_compliant} "
                f"exception(s) were identified."
            )
        else:
            return f"Unable to assess. {len(results)} finding(s) reviewed but determination was inconclusive."

    @staticmethod
    def _soc2_control_description(results: list[ControlResult], status: str) -> str:
        """Generate a fallback SOC 2 control description."""
        assessors: set[str] = set()
        for r in results:
            if r.assessor:
                assessors.add(r.assessor.split(":")[0])

        status_label = {
            "compliant": "operating effectively",
            "non_compliant": "not operating effectively",
            "partial": "partially effective",
            "not_assessed": "not yet assessed",
        }.get(status, status)

        return (
            f"The service organization has implemented controls assessed via "
            f"{', '.join(sorted(assessors)) or 'automated pipeline'}. "
            f"Based on {len(results)} finding(s), the control is {status_label}."
        )

    @staticmethod
    def _iso_justification(results: list[ControlResult], status: str) -> str:
        """Generate ISO SoA justification text."""
        if status == "compliant":
            return (
                f"Control is applicable and implemented. {len(results)} "
                f"evidence items confirm effective implementation."
            )
        elif status == "non_compliant":
            nc = sum(1 for r in results if r.status == "non_compliant")
            return (
                f"Control is applicable but requires remediation. "
                f"{nc} non-compliant finding(s) identified."
            )
        elif status == "partial":
            return (
                f"Control is applicable and partially implemented. "
                f"Some findings indicate gaps requiring attention."
            )
        return "Control is applicable. Assessment is in progress."

    @staticmethod
    def _iso_evidence_summary(results: list[ControlResult]) -> str:
        """Generate ISO SoA evidence summary."""
        sources: set[str] = set()
        assertions: set[str] = set()
        for r in results:
            if r.assessor:
                sources.add(r.assessor)
            if r.assertion_name:
                assertions.add(r.assertion_name)

        parts = [f"{len(results)} finding(s) evaluated"]
        if assertions:
            parts.append(f"assertions: {', '.join(sorted(assertions))}")
        if sources:
            parts.append(f"sources: {', '.join(sorted(sources))}")
        return ". ".join(parts) + "."

    @staticmethod
    def _markdown_to_html(md: str) -> str:
        """Basic markdown to HTML conversion.

        Handles headers, bold, tables, and lists. Not a full parser
        but sufficient for the structured output we generate.
        """
        import re

        lines = md.split("\n")
        html_lines: list[str] = []
        in_table = False
        in_list = False
        header_done = False

        for line in lines:
            stripped = line.strip()

            # Headers
            if stripped.startswith("### "):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                if in_table:
                    html_lines.append("</tbody></table>")
                    in_table = False
                text = _html.escape(stripped[4:])
                # Add status class
                css_class = ""
                if "[PASS]" in text:
                    text = text.replace("[PASS]", '<span class="pass">[PASS]</span>')
                elif "[FAIL]" in text:
                    text = text.replace("[FAIL]", '<span class="fail">[FAIL]</span>')
                elif "[PARTIAL]" in text:
                    text = text.replace("[PARTIAL]", '<span class="partial">[PARTIAL]</span>')
                html_lines.append(f"<h3>{text}</h3>")
                continue

            if stripped.startswith("## "):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                if in_table:
                    html_lines.append("</tbody></table>")
                    in_table = False
                html_lines.append(f"<h2>{_html.escape(stripped[3:])}</h2>")
                continue

            if stripped.startswith("# "):
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append(f"<h1>{_html.escape(stripped[2:])}</h1>")
                continue

            # Table separator line (skip)
            if stripped.startswith("|--") or stripped.startswith("| --"):
                continue

            # Table rows
            if stripped.startswith("|") and stripped.endswith("|"):
                cells = [_html.escape(c.strip()) for c in stripped.strip("|").split("|")]
                if not in_table:
                    html_lines.append("<table>")
                    # First row is header
                    html_lines.append("<thead><tr>")
                    for cell in cells:
                        html_lines.append(f"<th>{cell}</th>")
                    html_lines.append("</tr></thead><tbody>")
                    in_table = True
                    header_done = True
                else:
                    html_lines.append("<tr>")
                    for cell in cells:
                        html_lines.append(f"<td>{cell}</td>")
                    html_lines.append("</tr>")
                continue

            if in_table and not stripped.startswith("|"):
                html_lines.append("</tbody></table>")
                in_table = False

            # Lists
            if stripped.startswith("- "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                text = _html.escape(stripped[2:])
                # Bold
                text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
                html_lines.append(f"<li>{text}</li>")
                continue

            if in_list and not stripped.startswith("- "):
                html_lines.append("</ul>")
                in_list = False

            # Regular text with bold
            if stripped:
                text = _html.escape(stripped)
                text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
                # Handle line breaks (two trailing spaces)
                if text.endswith("  "):
                    text = text.rstrip() + "<br>"
                html_lines.append(f"<p>{text}</p>")
            elif not in_table and not in_list:
                # Empty line
                pass

        # Close any open elements
        if in_list:
            html_lines.append("</ul>")
        if in_table:
            html_lines.append("</tbody></table>")

        return "\n".join(html_lines)
