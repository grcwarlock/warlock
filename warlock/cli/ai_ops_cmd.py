"""AI-powered operational analysis commands.

Group: ``ai-ops``

Each command shows raw data by default and enables AI analysis when the
``--ai`` flag is provided.  All AI calls degrade gracefully when no provider
is configured -- raw data is always shown, AI output is additive.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import click
from rich.panel import Panel
from rich.table import Table

from warlock.cli import _check_ai_available, _parse_ai_response, cli, console, _error


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("ai-ops")
def ai_ops() -> None:
    """AI-powered GRC analysis: explain, predict, prioritize, draft."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_style(severity: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(severity.lower(), "")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _run_ai(task_value: str, context: dict, label: str) -> None:
    """Call the AI service for a generic task and print the response."""
    from warlock.ai.service import get_ai_service
    from warlock.ai.types import AITask

    svc = get_ai_service()
    try:
        task = AITask(task_value)
    except ValueError:
        # Fallback to FOLLOW_UP for tasks not in the enum
        task = AITask.FOLLOW_UP

    result = svc.reason(task=task, context=context)
    if result.ai_used:
        response_text = _parse_ai_response(result.value)
        console.print(Panel(response_text, title=f"[cyan]AI: {label}[/cyan]", border_style="cyan"))
        if result.token_usage:
            console.print(
                f"[dim]  tokens: {result.token_usage.input_tokens} in / "
                f"{result.token_usage.output_tokens} out  |  "
                f"latency: {result.latency_ms}ms[/dim]"
            )
    else:
        console.print(f"[dim](AI unavailable: {result.fallback_reason})[/dim]")


# ---------------------------------------------------------------------------
# explain-finding
# ---------------------------------------------------------------------------


@ai_ops.command("explain-finding")
@click.argument("finding_id")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI explanation")
def explain_finding(finding_id: str, use_ai: bool) -> None:
    """Explain what a finding means, why it matters, and how to fix it.

    FINDING_ID: finding UUID or prefix (from 'warlock findings list').
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()

    if not row:
        _error(f"Finding '{finding_id}' not found.")

    body = (
        f"[bold]{row.title}[/bold]\n\n"
        f"ID:               {row.id}\n"
        f"Severity:         {row.severity}\n"
        f"Observation Type: {row.observation_type}\n"
        f"Source:           {row.source} / {row.provider}\n"
        f"Resource:         {row.resource_type or '—'} — {row.resource_id or '—'}\n"
        f"Confidence:       {row.confidence}\n"
        f"Observed At:      {row.observed_at}"
    )
    console.print(Panel(body, title="[bold cyan]Finding[/bold cyan]", border_style="cyan"))

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "remediation_guidance",
        {
            "finding_id": row.id,
            "title": row.title,
            "severity": row.severity,
            "observation_type": row.observation_type,
            "source": row.source,
            "provider": row.provider,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "detail": json.dumps(row.detail or {}, default=str)[:2000],
            "question": (
                "Explain what this finding means, why it matters for compliance and security, "
                "and provide concrete remediation steps."
            ),
        },
        "Finding Explanation",
    )


# ---------------------------------------------------------------------------
# explain-control
# ---------------------------------------------------------------------------


@ai_ops.command("explain-control")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Framework (e.g. nist_800_53, soc2)")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI explanation")
def explain_control(control_id: str, framework: str | None, use_ai: bool) -> None:
    """Explain a control's purpose, current status, and what evidence is needed.

    CONTROL_ID: control identifier (e.g. AC-2, CC6.1).
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.control_id == control_id)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.order_by(ControlResult.assessed_at.desc()).limit(20).all()

    if not rows:
        console.print(f"[dim]No control results found for '{control_id}'.[/dim]")
    else:
        table = Table(title=f"Control Results: {control_id}")
        table.add_column("ID", style="dim", max_width=8)
        table.add_column("Framework")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("Assessor")
        table.add_column("Assessed At")
        for r in rows:
            table.add_row(
                r.id[:8],
                r.framework,
                r.status,
                r.severity,
                (r.assessor or "")[:30],
                str(r.assessed_at)[:19] if r.assessed_at else "—",
            )
        console.print(table)

    if not _check_ai_available(use_ai):
        return

    status_summary = (
        {r.status: 0 for r in rows} if rows else {}
    )
    for r in rows:
        status_summary[r.status] = status_summary.get(r.status, 0) + 1

    _run_ai(
        "governance_analysis",
        {
            "control_id": control_id,
            "framework": framework or "any",
            "result_count": len(rows),
            "status_distribution": status_summary,
            "latest_status": rows[0].status if rows else "not_assessed",
            "latest_severity": rows[0].severity if rows else "unknown",
            "remediation_summary": rows[0].remediation_summary if rows else None,
            "question": (
                "Explain the purpose of this control, what its current status indicates, "
                "what evidence is typically required to satisfy it, and what actions "
                "should be taken to achieve compliance."
            ),
        },
        f"Control Explanation: {control_id}",
    )


# ---------------------------------------------------------------------------
# root-cause
# ---------------------------------------------------------------------------


@ai_ops.command("root-cause")
@click.argument("finding_id")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI root cause analysis")
def root_cause(finding_id: str, use_ai: bool) -> None:
    """AI root cause analysis from a finding and its control mappings.

    FINDING_ID: finding UUID or prefix (from 'warlock findings list').
    Uses the finding's detail, linked control mappings, and source data
    to produce a structured root cause analysis.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, ControlMapping

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not row:
            _error(f"Finding '{finding_id}' not found.")

        mappings = (
            session.query(ControlMapping)
            .filter(ControlMapping.finding_id == row.id)
            .limit(10)
            .all()
        )

    console.print(Panel(
        f"[bold]{row.title}[/bold]\n\n"
        f"ID:               {row.id}\n"
        f"Severity:         {row.severity}\n"
        f"Observation Type: {row.observation_type}\n"
        f"Source:           {row.source} / {row.provider}\n"
        f"Resource:         {row.resource_type or '—'} — {row.resource_id or '—'}\n"
        f"Observed At:      {row.observed_at}",
        title="[bold cyan]Finding[/bold cyan]",
        border_style="cyan",
    ))

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "governance_analysis",
        {
            "finding_id": row.id,
            "title": row.title,
            "observation_type": row.observation_type,
            "severity": row.severity,
            "source": row.source,
            "provider": row.provider,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "detail": json.dumps(row.detail or {}, default=str)[:2000],
            "mapped_controls": [
                {"framework": m.framework, "control_id": m.control_id} for m in mappings
            ],
            "question": (
                "Perform a root cause analysis for this finding. "
                "Identify the underlying cause (not just the symptom), "
                "contributing factors, and systemic weaknesses. "
                "Explain how this finding arose and what preventive controls "
                "would stop it from recurring."
            ),
        },
        "Root Cause Analysis",
    )


# ---------------------------------------------------------------------------
# predict-risk
# ---------------------------------------------------------------------------


@ai_ops.command("predict-risk")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option("--limit", "-n", default=20, help="Controls to analyse")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI prediction")
def predict_risk(framework: str | None, limit: int, use_ai: bool) -> None:
    """Predict which controls are likely to fail based on historical trends."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.control_id,
            func.count(ControlResult.id).label("total"),
            func.sum(
                (ControlResult.status == "non_compliant").cast(int)  # type: ignore[arg-type]
            ).label("failures"),
        ).group_by(ControlResult.framework, ControlResult.control_id)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.order_by(func.sum(
            (ControlResult.status == "non_compliant").cast(int)  # type: ignore[arg-type]
        ).desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No control results found.[/dim]")
        return

    table = Table(title="Control Risk Profile (by historical failures)")
    table.add_column("Framework", style="cyan")
    table.add_column("Control ID")
    table.add_column("Total", justify="right")
    table.add_column("Failures", justify="right")
    table.add_column("Failure Rate", justify="right")

    risk_data = []
    for r in rows:
        failures = int(r.failures or 0)
        total = int(r.total or 0)
        rate = failures / total if total else 0.0
        style = "red" if rate > 0.5 else "yellow" if rate > 0.2 else "green"
        table.add_row(
            r.framework,
            r.control_id,
            str(total),
            str(failures),
            f"[{style}]{rate:.0%}[/{style}]",
        )
        risk_data.append({
            "framework": r.framework,
            "control_id": r.control_id,
            "total": total,
            "failures": failures,
            "failure_rate": round(rate, 3),
        })
    console.print(table)

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "risk_narrative",
        {
            "framework": framework or "all",
            "controls_analysed": len(risk_data),
            "top_risk_controls": risk_data[:10],
            "question": (
                "Based on this historical failure data, predict which controls are most "
                "likely to fail next. Explain the patterns you see and recommend "
                "proactive remediation priorities."
            ),
        },
        "Risk Prediction",
    )


# ---------------------------------------------------------------------------
# suggest-remediation
# ---------------------------------------------------------------------------


@ai_ops.command("suggest-remediation")
@click.argument("finding_id")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI suggestions")
def suggest_remediation(finding_id: str, use_ai: bool) -> None:
    """AI-suggested remediation steps for a finding.

    FINDING_ID: finding UUID or prefix.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, ControlMapping

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not row:
            _error(f"Finding '{finding_id}' not found.")

        mappings = (
            session.query(ControlMapping)
            .filter(ControlMapping.finding_id == row.id)
            .limit(10)
            .all()
        )
        mapped_controls = [
            {"framework": m.framework, "control_id": m.control_id} for m in mappings
        ]

    console.print(
        f"[bold]{row.title}[/bold]  [{row.severity}]  {row.source}/{row.provider}"
    )
    if mapped_controls:
        console.print(
            "[dim]Mapped controls: "
            + ", ".join(f"{m['framework']}/{m['control_id']}" for m in mapped_controls)
            + "[/dim]"
        )

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "remediation_guidance",
        {
            "finding_id": row.id,
            "title": row.title,
            "severity": row.severity,
            "observation_type": row.observation_type,
            "source": row.source,
            "provider": row.provider,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "detail": json.dumps(row.detail or {}, default=str)[:2000],
            "mapped_controls": mapped_controls,
            "question": (
                "Provide concrete, prioritized remediation steps for this finding. "
                "Include CLI commands, console steps, or policy changes where applicable. "
                "Note any quick wins versus longer-term fixes."
            ),
        },
        "Remediation Suggestions",
    )


# ---------------------------------------------------------------------------
# prioritize
# ---------------------------------------------------------------------------


@ai_ops.command("prioritize")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=30, help="Findings to consider")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI prioritization")
def prioritize(framework: str | None, limit: int, use_ai: bool) -> None:
    """AI-prioritized list of what to fix first."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(
            ControlResult.status == "non_compliant"
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.order_by(ControlResult.assessed_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No non-compliant controls found.[/dim]")
        return

    table = Table(title=f"Non-Compliant Controls ({len(rows)})")
    table.add_column("Control", style="cyan")
    table.add_column("Framework")
    table.add_column("Severity")
    table.add_column("Assessor")
    table.add_column("Assessed At")
    for r in rows:
        sty = _severity_style(r.severity)
        table.add_row(
            r.control_id,
            r.framework,
            f"[{sty}]{r.severity}[/{sty}]" if sty else r.severity,
            (r.assessor or "")[:25],
            str(r.assessed_at)[:10] if r.assessed_at else "—",
        )
    console.print(table)

    if not _check_ai_available(use_ai):
        return

    items = [
        {
            "control_id": r.control_id,
            "framework": r.framework,
            "severity": r.severity,
            "remediation_summary": r.remediation_summary or "",
        }
        for r in rows
    ]
    _run_ai(
        "risk_narrative",
        {
            "framework": framework or "all",
            "non_compliant_count": len(rows),
            "non_compliant_controls": items,
            "question": (
                "Prioritize these non-compliant controls for remediation. "
                "Group by urgency (immediate / short-term / long-term). "
                "Consider severity, framework impact, and remediation complexity."
            ),
        },
        "Remediation Priorities",
    )


# ---------------------------------------------------------------------------
# summarize-posture
# ---------------------------------------------------------------------------


@ai_ops.command("summarize-posture")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI summary")
def summarize_posture(framework: str | None, use_ai: bool) -> None:
    """Natural language compliance posture summary."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        q = session.query(
            ControlResult.status,
            func.count(ControlResult.id).label("cnt"),
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.group_by(ControlResult.status).all()

    if not rows:
        console.print("[dim]No control results found.[/dim]")
        return

    total = sum(r.cnt for r in rows)
    status_dist = {r.status: r.cnt for r in rows}

    table = Table(title="Compliance Posture" + (f" — {framework}" if framework else ""))
    table.add_column("Status", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Percent", justify="right")
    for status, cnt in sorted(status_dist.items(), key=lambda x: -x[1]):
        pct = cnt / total * 100 if total else 0
        table.add_row(status, str(cnt), f"{pct:.1f}%")
    console.print(table)
    console.print(f"\n[dim]Total control results: {total}[/dim]")

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "executive_report",
        {
            "framework": framework or "all",
            "total_controls": total,
            "status_distribution": status_dist,
            "question": (
                "Provide a 3-5 sentence executive summary of this compliance posture. "
                "Highlight the most significant risks, overall health score, and "
                "top recommendations."
            ),
        },
        "Posture Summary",
    )


# ---------------------------------------------------------------------------
# draft-poam
# ---------------------------------------------------------------------------


@ai_ops.command("draft-poam")
@click.argument("finding_id")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI drafting")
def draft_poam(finding_id: str, use_ai: bool) -> None:
    """Auto-draft a POA&M entry from a finding.

    FINDING_ID: finding UUID or prefix.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, ControlMapping

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not row:
            _error(f"Finding '{finding_id}' not found.")

        mappings = (
            session.query(ControlMapping)
            .filter(ControlMapping.finding_id == row.id)
            .limit(5)
            .all()
        )

    console.print(f"[bold]Draft POA&M for Finding:[/bold] {row.title}")
    console.print(f"  Severity: {row.severity} | Source: {row.source}/{row.provider}")

    if not _check_ai_available(use_ai):
        console.print(
            "\n[dim]Enable --ai to generate a full POA&M draft with weakness description, "
            "scheduled completion, milestones, and remediation steps.[/dim]"
        )
        return

    _run_ai(
        "remediation_guidance",
        {
            "finding_id": row.id,
            "title": row.title,
            "severity": row.severity,
            "observation_type": row.observation_type,
            "source": row.source,
            "provider": row.provider,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "detail": json.dumps(row.detail or {}, default=str)[:2000],
            "mapped_controls": [
                {"framework": m.framework, "control_id": m.control_id} for m in mappings
            ],
            "question": (
                "Draft a complete POA&M (Plan of Action and Milestones) entry for this finding. "
                "Include: weakness_description, scheduled_completion (ISO date), "
                "milestones (list with target dates), resources_required, and "
                "remediation_steps. Format as structured text."
            ),
        },
        "POA&M Draft",
    )


# ---------------------------------------------------------------------------
# draft-exception
# ---------------------------------------------------------------------------


@ai_ops.command("draft-exception")
@click.argument("finding_id")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI drafting")
def draft_exception(finding_id: str, use_ai: bool) -> None:
    """Auto-draft a policy exception request with justification.

    FINDING_ID: finding UUID or prefix.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not row:
            _error(f"Finding '{finding_id}' not found.")

    console.print(f"[bold]Draft Exception for:[/bold] {row.title}")
    console.print(f"  Severity: {row.severity} | Source: {row.source}/{row.provider}")

    if not _check_ai_available(use_ai):
        console.print(
            "\n[dim]Enable --ai to generate an exception draft with business justification, "
            "compensating controls, and risk acceptance rationale.[/dim]"
        )
        return

    _run_ai(
        "governance_analysis",
        {
            "finding_id": row.id,
            "title": row.title,
            "severity": row.severity,
            "observation_type": row.observation_type,
            "source": row.source,
            "provider": row.provider,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "detail": json.dumps(row.detail or {}, default=str)[:2000],
            "question": (
                "Draft a policy exception request for this finding. Include: "
                "exception_title, business_justification, risk_description, "
                "compensating_controls, residual_risk_level, requested_duration, "
                "and approver_guidance. Format as structured text suitable for review."
            ),
        },
        "Exception Draft",
    )


# ---------------------------------------------------------------------------
# analyze-vendor
# ---------------------------------------------------------------------------


@ai_ops.command("analyze-vendor")
@click.argument("vendor_id")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI analysis")
def analyze_vendor(vendor_id: str, use_ai: bool) -> None:
    """AI vendor risk analysis.

    VENDOR_ID: vendor UUID or prefix (from 'warlock vendor-mgmt list').
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Vendor

    init_db()
    with get_session() as session:
        row = session.query(Vendor).filter(Vendor.id.startswith(vendor_id)).first()

    if not row:
        _error(f"Vendor '{vendor_id}' not found.")

    body = (
        f"[bold]{row.name}[/bold]\n\n"
        f"ID:           {row.id}\n"
        f"Tier:         {getattr(row, 'tier', '—')}\n"
        f"Risk Score:   {getattr(row, 'risk_score', '—')}\n"
        f"Status:       {getattr(row, 'status', '—')}\n"
        f"Country:      {getattr(row, 'country', '—')}\n"
    )
    console.print(Panel(body, title="[bold cyan]Vendor[/bold cyan]", border_style="cyan"))

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "vendor_risk_analysis",
        {
            "vendor_id": row.id,
            "vendor_name": row.name,
            "tier": getattr(row, "tier", None),
            "risk_score": getattr(row, "risk_score", None),
            "status": getattr(row, "status", None),
            "country": getattr(row, "country", None),
            "services": getattr(row, "services", None),
            "data_types": getattr(row, "data_types", None),
            "question": (
                "Provide a comprehensive vendor risk assessment. Cover: overall risk rating, "
                "key risk factors, data exposure concerns, regulatory implications, "
                "and recommended controls or mitigations."
            ),
        },
        f"Vendor Risk Analysis: {row.name}",
    )


# ---------------------------------------------------------------------------
# review-evidence
# ---------------------------------------------------------------------------


@ai_ops.command("review-evidence")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Framework filter")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI review")
def review_evidence(control_id: str, framework: str | None, use_ai: bool) -> None:
    """AI review of evidence sufficiency for a control.

    CONTROL_ID: control identifier (e.g. AC-2).
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.control_id == control_id)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.order_by(ControlResult.assessed_at.desc()).limit(10).all()

    if not rows:
        console.print(f"[dim]No control results for '{control_id}'.[/dim]")
        return

    table = Table(title=f"Evidence for {control_id}")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Status")
    table.add_column("Assessor")
    table.add_column("AI Assessment", max_width=60)
    table.add_column("Assessed At")
    for r in rows:
        table.add_row(
            r.id[:8],
            r.status,
            (r.assessor or "")[:25],
            (r.ai_assessment or "")[:60],
            str(r.assessed_at)[:10] if r.assessed_at else "—",
        )
    console.print(table)

    if not _check_ai_available(use_ai):
        return

    evidence_items = [
        {
            "result_id": r.id[:8],
            "status": r.status,
            "assessor": r.assessor,
            "assertion_name": r.assertion_name,
            "assertion_passed": r.assertion_passed,
            "ai_assessment": r.ai_assessment,
            "ai_confidence": r.ai_confidence,
            "evidence_ids": r.evidence_ids,
        }
        for r in rows
    ]
    _run_ai(
        "evidence_evaluation",
        {
            "control_id": control_id,
            "framework": framework or "any",
            "evidence_count": len(evidence_items),
            "evidence_items": evidence_items,
            "question": (
                "Evaluate the sufficiency of this evidence for the control. "
                "Is the evidence complete? Are there gaps? What additional evidence "
                "would an auditor require? Rate sufficiency: sufficient / partial / insufficient."
            ),
        },
        f"Evidence Review: {control_id}",
    )


# ---------------------------------------------------------------------------
# classify-finding
# ---------------------------------------------------------------------------


@ai_ops.command("classify-finding")
@click.argument("finding_id")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI classification")
def classify_finding(finding_id: str, use_ai: bool) -> None:
    """Auto-classify a finding by observation type and severity.

    FINDING_ID: finding UUID or prefix.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        row = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()

    if not row:
        _error(f"Finding '{finding_id}' not found.")

    console.print(
        f"[bold]{row.title}[/bold]\n"
        f"  Current classification: {row.observation_type} / {row.severity}"
    )

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "issue_triage",
        {
            "finding_id": row.id,
            "title": row.title,
            "current_observation_type": row.observation_type,
            "current_severity": row.severity,
            "source": row.source,
            "provider": row.provider,
            "resource_type": row.resource_type,
            "detail": json.dumps(row.detail or {}, default=str)[:2000],
            "question": (
                "Classify this finding. Determine the correct observation_type "
                "(misconfiguration, vulnerability, alert, policy_violation, access_anomaly, inventory) "
                "and severity (critical, high, medium, low, info). "
                "Explain your reasoning and flag if the current classification is incorrect."
            ),
        },
        "Finding Classification",
    )


# ---------------------------------------------------------------------------
# detect-drift
# ---------------------------------------------------------------------------


@ai_ops.command("detect-drift")
@click.option("--framework", "-f", default=None, help="Framework to check")
@click.option("--days", "-d", default=30, help="Look-back window in days")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI drift analysis")
def detect_drift(framework: str | None, days: int, use_ai: bool) -> None:
    """Detect compliance drift patterns over a time window."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id).label("cnt"),
        ).filter(ControlResult.assessed_at >= since)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.group_by(ControlResult.framework, ControlResult.status).all()

    if not rows:
        console.print(f"[dim]No control results in the last {days} days.[/dim]")
        return

    # Aggregate by framework
    fw_stats: dict[str, dict[str, int]] = {}
    for r in rows:
        fw_stats.setdefault(r.framework, {})[r.status] = r.cnt

    table = Table(title=f"Compliance Drift (last {days} days)")
    table.add_column("Framework", style="cyan")
    table.add_column("Compliant", justify="right")
    table.add_column("Non-Compliant", justify="right")
    table.add_column("Partial", justify="right")
    table.add_column("Total", justify="right")
    for fw, statuses in sorted(fw_stats.items()):
        compliant = statuses.get("compliant", 0) + statuses.get("inherited_compliant", 0)
        non_compliant = statuses.get("non_compliant", 0)
        partial = statuses.get("partial", 0)
        total = sum(statuses.values())
        table.add_row(fw, str(compliant), str(non_compliant), str(partial), str(total))
    console.print(table)

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "drift_explanation",
        {
            "framework": framework or "all",
            "period_days": days,
            "framework_stats": fw_stats,
            "question": (
                "Analyse these compliance results for drift patterns. "
                "Which frameworks or controls show the most concerning trends? "
                "What are the likely causes? What should be done immediately?"
            ),
        },
        "Drift Analysis",
    )


# ---------------------------------------------------------------------------
# forecast
# ---------------------------------------------------------------------------


@ai_ops.command("forecast")
@click.option("--framework", "-f", default=None, help="Framework to forecast")
@click.option("--days", "-d", default=90, help="Forecast horizon in days")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI forecast")
def forecast(framework: str | None, days: int, use_ai: bool) -> None:
    """Forecast compliance trajectory over a time horizon."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id).label("cnt"),
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        recent = q.filter(
            ControlResult.assessed_at >= _utcnow() - timedelta(days=30)
        ).group_by(ControlResult.framework, ControlResult.status).all()

        older = q.filter(
            ControlResult.assessed_at >= _utcnow() - timedelta(days=90),
            ControlResult.assessed_at < _utcnow() - timedelta(days=30),
        ).group_by(ControlResult.framework, ControlResult.status).all()

    def _agg(rows: list) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for r in rows:
            out.setdefault(r.framework, {})[r.status] = r.cnt
        return out

    recent_agg = _agg(recent)
    older_agg = _agg(older)

    if not recent_agg:
        console.print("[dim]No recent control results to forecast from.[/dim]")
        return

    table = Table(title="Compliance Snapshot (last 30 days vs prior 60 days)")
    table.add_column("Framework", style="cyan")
    table.add_column("Recent Compliant", justify="right")
    table.add_column("Prior Compliant", justify="right")
    table.add_column("Trend")
    for fw, statuses in sorted(recent_agg.items()):
        recent_ok = statuses.get("compliant", 0)
        prior_ok = older_agg.get(fw, {}).get("compliant", 0)
        trend = (
            "[green]improving[/green]"
            if recent_ok > prior_ok
            else "[red]declining[/red]"
            if recent_ok < prior_ok
            else "[dim]stable[/dim]"
        )
        table.add_row(fw, str(recent_ok), str(prior_ok), trend)
    console.print(table)

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "risk_narrative",
        {
            "framework": framework or "all",
            "forecast_horizon_days": days,
            "recent_30_days": recent_agg,
            "prior_60_days": older_agg,
            "question": (
                f"Based on these compliance trends, forecast the compliance trajectory "
                f"over the next {days} days. "
                "Identify frameworks at risk of significant degradation and recommend "
                "actions to reverse negative trends."
            ),
        },
        f"Compliance Forecast ({days}-day horizon)",
    )


# ---------------------------------------------------------------------------
# audit-readiness
# ---------------------------------------------------------------------------


@ai_ops.command("audit-readiness")
@click.option("--framework", "-f", default=None, help="Framework to assess")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI assessment")
def audit_readiness(framework: str | None, use_ai: bool) -> None:
    """AI assessment of audit readiness for a framework."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id).label("cnt"),
        )
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.group_by(ControlResult.framework, ControlResult.status).all()

    if not rows:
        console.print("[dim]No control results found.[/dim]")
        return

    fw_stats: dict[str, dict[str, int]] = {}
    for r in rows:
        fw_stats.setdefault(r.framework, {})[r.status] = r.cnt

    table = Table(title="Audit Readiness" + (f" — {framework}" if framework else ""))
    table.add_column("Framework", style="cyan")
    table.add_column("Compliant", justify="right")
    table.add_column("Non-Compliant", justify="right")
    table.add_column("Partial", justify="right")
    table.add_column("Readiness %", justify="right")
    for fw, statuses in sorted(fw_stats.items()):
        compliant = statuses.get("compliant", 0) + statuses.get("inherited_compliant", 0)
        non_compliant = statuses.get("non_compliant", 0)
        partial = statuses.get("partial", 0)
        total = sum(statuses.values())
        pct = compliant / total * 100 if total else 0
        style = "green" if pct >= 80 else "yellow" if pct >= 60 else "red"
        table.add_row(
            fw,
            str(compliant),
            str(non_compliant),
            str(partial),
            f"[{style}]{pct:.0f}%[/{style}]",
        )
    console.print(table)

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "audit_readiness",
        {
            "framework": framework or "all",
            "framework_stats": fw_stats,
            "question": (
                "Provide an audit readiness assessment. "
                "For each framework, rate readiness (ready / at-risk / not-ready), "
                "identify the top 3 blockers, and suggest actions to achieve audit readiness "
                "within 30 days."
            ),
        },
        "Audit Readiness Assessment",
    )


# ---------------------------------------------------------------------------
# brief
# ---------------------------------------------------------------------------


@ai_ops.command("brief")
@click.option("--framework", "-f", default=None, help="Limit to a framework")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI briefing")
def brief(framework: str | None, use_ai: bool) -> None:
    """Generate an AI-powered compliance briefing."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        result_q = session.query(
            ControlResult.status,
            func.count(ControlResult.id).label("cnt"),
        )
        if framework:
            result_q = result_q.filter(ControlResult.framework == framework)
        result_rows = result_q.group_by(ControlResult.status).all()

        finding_q = session.query(
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        finding_rows = finding_q.group_by(Finding.severity).all()

    status_dist = {r.status: r.cnt for r in result_rows}
    sev_dist = {r.severity: r.cnt for r in finding_rows}
    total_results = sum(status_dist.values())
    total_findings = sum(sev_dist.values())

    console.print("\n[bold]Compliance Brief[/bold]" + (f" — {framework}" if framework else ""))
    console.print(f"  Control results: {total_results}")
    console.print(f"  Findings:        {total_findings}")

    if status_dist:
        compliant = (
            status_dist.get("compliant", 0) + status_dist.get("inherited_compliant", 0)
        )
        non_compliant = status_dist.get("non_compliant", 0)
        pct = compliant / total_results * 100 if total_results else 0
        console.print(
            f"  Compliant: [green]{compliant}[/green]  "
            f"Non-compliant: [red]{non_compliant}[/red]  "
            f"({pct:.0f}% compliant)"
        )

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "executive_report",
        {
            "framework": framework or "all",
            "total_control_results": total_results,
            "status_distribution": status_dist,
            "finding_severity_distribution": sev_dist,
            "question": (
                "Generate a concise compliance briefing suitable for a CISO or board audience. "
                "Include: executive summary, key risks, compliance score, "
                "top priorities, and recommended actions this week."
            ),
        },
        "Compliance Briefing",
    )


# ---------------------------------------------------------------------------
# ask
# ---------------------------------------------------------------------------


@ai_ops.command("ask")
@click.argument("question")
@click.option(
    "--context",
    "ctx_scope",
    type=click.Choice(["framework", "findings", "incidents", "all"]),
    default="all",
    help="Data scope to load as context",
)
@click.option("--framework", "-f", default=None, help="Framework filter (when scope=framework)")
def ask_grc(question: str, ctx_scope: str, framework: str | None) -> None:
    """Open-ended AI Q&A about your GRC data.

    QUESTION: free-text question about compliance, risk, or findings.

    Examples:

    \b
      warlock ai-ops ask "What are my top 3 risks?" --context all
      warlock ai-ops ask "How ready am I for a SOC 2 audit?" --context framework -f soc2
    """
    from warlock.cli import _check_ai_available

    if not _check_ai_available(True):
        return

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding
    from warlock.ai.service import get_ai_service
    from warlock.ai.types import ConversationContext

    init_db()
    context_data: dict = {"question": question, "scope": ctx_scope}

    with get_session() as session:
        if ctx_scope in ("framework", "all"):
            from sqlalchemy import func
            q = session.query(
                ControlResult.framework,
                ControlResult.status,
                func.count(ControlResult.id).label("cnt"),
            )
            if framework:
                q = q.filter(ControlResult.framework == framework)
            rows = q.group_by(ControlResult.framework, ControlResult.status).all()
            context_data["control_status_distribution"] = [
                {"framework": r.framework, "status": r.status, "count": r.cnt}
                for r in rows
            ]

        if ctx_scope in ("findings", "all"):
            from sqlalchemy import func
            sev_rows = (
                session.query(Finding.severity, func.count(Finding.id).label("cnt"))
                .group_by(Finding.severity)
                .all()
            )
            context_data["finding_severity_distribution"] = {
                r.severity: r.cnt for r in sev_rows
            }

    svc = get_ai_service()
    session_id = str(uuid.uuid4())
    ctx = ConversationContext(
        entity_type="grc_platform",
        entity_id="global",
        entity_data=context_data,
        compliance_context={"question": question},
    )
    result = svc.converse(session_id=session_id, message=question, context=ctx)
    if result.ai_used:
        console.print(Panel(
            _parse_ai_response(result.value),
            title="[cyan]AI Answer[/cyan]",
            border_style="cyan",
        ))
    else:
        console.print(f"[yellow]AI unavailable: {result.fallback_reason}[/yellow]")


# ---------------------------------------------------------------------------
# batch-classify
# ---------------------------------------------------------------------------


@ai_ops.command("batch-classify")
@click.option("--source", "-s", multiple=True, help="Limit to source(s) (repeatable)")
@click.option("--dry-run", is_flag=True, default=False, help="Show classifications without saving")
@click.option("--limit", "-n", default=50, help="Max findings to classify")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI classification")
def batch_classify(
    source: tuple[str, ...],
    dry_run: bool,
    limit: int,
    use_ai: bool,
) -> None:
    """Batch AI classification of findings by observation type and severity."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding

    init_db()
    with get_session() as session:
        q = session.query(Finding)
        if source:
            q = q.filter(Finding.source.in_(list(source)))
        rows = q.order_by(Finding.observed_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No findings to classify.[/dim]")
        return

    console.print(f"[bold]Batch Classification[/bold] — {len(rows)} findings")
    if dry_run:
        console.print("[dim](dry-run — no changes will be saved)[/dim]")

    table = Table(title="Findings for Classification")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Current Type")
    table.add_column("Severity")
    table.add_column("Title", max_width=50)
    table.add_column("Source")
    for r in rows:
        table.add_row(r.id[:8], r.observation_type, r.severity, r.title[:50], r.source)
    console.print(table)

    if not _check_ai_available(use_ai):
        return

    console.print(f"[dim]Classifying {len(rows)} findings via AI...[/dim]")

    # Summarise findings in bulk for the AI -- keep payload manageable
    batch_summary = [
        {
            "id": r.id[:8],
            "title": r.title,
            "current_observation_type": r.observation_type,
            "current_severity": r.severity,
            "source": r.source,
            "provider": r.provider,
        }
        for r in rows
    ]

    _run_ai(
        "issue_triage",
        {
            "total_findings": len(rows),
            "findings": batch_summary,
            "question": (
                "For each finding, suggest the correct observation_type and severity. "
                "Flag any findings where the current classification appears incorrect. "
                "Return a summary table: id | suggested_type | suggested_severity | needs_reclassification."
            ),
        },
        f"Batch Classification ({len(rows)} findings)",
    )
