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

from rich.markup import escape

from warlock.cli import _check_ai_available, _parse_ai_response, cli, console, _error


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("ai-ops", invoke_without_command=True)
@click.pass_context
def ai_ops(ctx: click.Context) -> None:
    """AI-powered GRC analysis: explain, predict, prioritize, draft."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


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

    status_summary = {r.status: 0 for r in rows} if rows else {}
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

    console.print(
        Panel(
            f"[bold]{row.title}[/bold]\n\n"
            f"ID:               {row.id}\n"
            f"Severity:         {row.severity}\n"
            f"Observation Type: {row.observation_type}\n"
            f"Source:           {row.source} / {row.provider}\n"
            f"Resource:         {row.resource_type or '—'} — {row.resource_id or '—'}\n"
            f"Observed At:      {row.observed_at}",
            title="[bold cyan]Finding[/bold cyan]",
            border_style="cyan",
        )
    )

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
        rows = (
            q.order_by(
                func.sum(
                    (ControlResult.status == "non_compliant").cast(int)  # type: ignore[arg-type]
                ).desc()
            )
            .limit(limit)
            .all()
        )

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
        risk_data.append(
            {
                "framework": r.framework,
                "control_id": r.control_id,
                "total": total,
                "failures": failures,
                "failure_rate": round(rate, 3),
            }
        )
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
        mapped_controls = [{"framework": m.framework, "control_id": m.control_id} for m in mappings]

    console.print(
        f"[bold]{escape(row.title or '')}[/bold]  [{row.severity}]  {row.source}/{row.provider}"
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
        q = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
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
            session.query(ControlMapping).filter(ControlMapping.finding_id == row.id).limit(5).all()
        )

    console.print(f"[bold]Draft POA&M for Finding:[/bold] {escape(row.title or '')}")
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

    console.print(f"[bold]Draft Exception for:[/bold] {escape(row.title or '')}")
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
        recent = (
            q.filter(ControlResult.assessed_at >= _utcnow() - timedelta(days=30))
            .group_by(ControlResult.framework, ControlResult.status)
            .all()
        )

        older = (
            q.filter(
                ControlResult.assessed_at >= _utcnow() - timedelta(days=90),
                ControlResult.assessed_at < _utcnow() - timedelta(days=30),
            )
            .group_by(ControlResult.framework, ControlResult.status)
            .all()
        )

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
        compliant = status_dist.get("compliant", 0) + status_dist.get("inherited_compliant", 0)
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
                {"framework": r.framework, "status": r.status, "count": r.cnt} for r in rows
            ]

        if ctx_scope in ("findings", "all"):
            from sqlalchemy import func

            sev_rows = (
                session.query(Finding.severity, func.count(Finding.id).label("cnt"))
                .group_by(Finding.severity)
                .all()
            )
            context_data["finding_severity_distribution"] = {r.severity: r.cnt for r in sev_rows}

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
        console.print(
            Panel(
                _parse_ai_response(result.value),
                title="[cyan]AI Answer[/cyan]",
                border_style="cyan",
            )
        )
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
        table.add_row(
            r.id[:8],
            r.observation_type,
            r.severity,
            escape(r.title[:50] if r.title else ""),
            r.source,
        )
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


# ---------------------------------------------------------------------------
# horizon-scan
# ---------------------------------------------------------------------------


@ai_ops.command("horizon-scan")
@click.option("--framework", "-f", multiple=True, help="Framework(s) to scan (repeatable)")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI advisory generation")
def horizon_scan(framework: tuple[str, ...], use_ai: bool) -> None:
    """Regulatory horizon scanning -- upcoming deadlines and emerging requirements."""
    from warlock.db.engine import get_session, init_db
    from warlock.ai.horizon_scanning import HorizonScanner

    init_db()
    fw_list: list[str] | None = list(framework) if framework else None

    with get_session() as session:
        scanner = HorizonScanner(session)
        changes = scanner.scan_regulatory_changes(fw_list)
        advisory = scanner.generate_advisory(changes)

    # Regulatory calendar table
    if advisory.deadlines:
        table = Table(title="Regulatory Calendar")
        table.add_column("Regulation", style="cyan", max_width=40)
        table.add_column("Effective Date")
        table.add_column("Impact", justify="center")
        table.add_column("Frameworks Affected", max_width=30)
        table.add_column("Action Required", max_width=50)

        for d in advisory.deadlines:
            impact_style = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(d.impact_level, "")
            table.add_row(
                escape(d.regulation),
                str(d.effective_date),
                f"[{impact_style}]{d.impact_level}[/{impact_style}]"
                if impact_style
                else d.impact_level,
                ", ".join(d.frameworks_affected),
                escape(d.action_required[:50]) + ("..." if len(d.action_required) > 50 else ""),
            )
        console.print(table)
    else:
        console.print("[dim]No regulatory deadlines match the selected frameworks.[/dim]")

    # Emerging requirements
    if advisory.emerging_requirements:
        console.print()
        em_table = Table(title="Emerging Requirements (Pattern Detection)")
        em_table.add_column("Framework", style="cyan")
        em_table.add_column("Pattern")
        em_table.add_column("Confidence", justify="right")
        em_table.add_column("Affected Controls", max_width=30)
        em_table.add_column("Description", max_width=50)

        for req in advisory.emerging_requirements:
            conf_style = (
                "green" if req.confidence >= 0.7 else "yellow" if req.confidence >= 0.4 else "dim"
            )
            em_table.add_row(
                req.framework,
                req.pattern_type,
                f"[{conf_style}]{req.confidence:.0%}[/{conf_style}]",
                ", ".join(req.affected_controls[:5])
                + ("..." if len(req.affected_controls) > 5 else ""),
                escape(req.description[:50]) + ("..." if len(req.description) > 50 else ""),
            )
        console.print(em_table)

    # Summary panel
    risk_style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green"}.get(
        advisory.risk_level, ""
    )
    console.print(
        Panel(
            f"Overall Risk Level: [{risk_style}]{advisory.risk_level.upper()}[/{risk_style}]\n\n"
            + escape(advisory.summary),
            title="[bold]Horizon Scan Summary[/bold]",
            border_style="cyan",
        )
    )

    if not _check_ai_available(use_ai):
        return

    change_data = [
        {
            "source": c.source,
            "regulation": c.regulation,
            "impact_level": c.impact_level,
            "frameworks_affected": c.frameworks_affected,
            "description": c.description[:200],
        }
        for c in changes
    ]
    _run_ai(
        "governance_analysis",
        {
            "regulatory_changes": change_data,
            "total_changes": len(changes),
            "risk_level": advisory.risk_level,
            "question": (
                "Analyze these regulatory changes and emerging requirements. "
                "Provide a prioritized action plan with specific steps, timelines, "
                "and resource estimates for achieving compliance. "
                "Highlight any cross-framework synergies."
            ),
        },
        "Regulatory Horizon Advisory",
    )


# ---------------------------------------------------------------------------
# devtools (subgroup)
# ---------------------------------------------------------------------------


@ai_ops.group("devtools", invoke_without_command=True)
@click.pass_context
def devtools_group(ctx: click.Context) -> None:
    """AI assessment debugging and inspection tools."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@devtools_group.command("inspect")
@click.argument("control_result_id")
def devtools_inspect(control_result_id: str) -> None:
    """Inspect a single AI assessment -- prompt, response, confidence.

    CONTROL_RESULT_ID: UUID or prefix of the control result.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.ai.devtools import AIDevTools

    init_db()
    with get_session() as session:
        tools = AIDevTools(session)
        info = tools.inspect_assessment(control_result_id)

    if info is None:
        _error(f"Control result '{control_result_id}' not found.")

    # Assessment overview
    body = (
        f"[bold]Control Result:[/bold] {info.control_result_id}\n"
        f"Framework:    {info.framework}\n"
        f"Control ID:   {info.control_id}\n"
        f"Status:       {info.status}\n"
        f"Severity:     {info.severity}\n"
        f"Assessor:     {info.assessor}\n"
        f"Assessed At:  {info.assessed_at or '---'}\n"
        f"Finding ID:   {info.finding_id}\n"
    )
    console.print(
        Panel(body, title="[bold cyan]Assessment Overview[/bold cyan]", border_style="cyan")
    )

    # Assertion details
    if info.assertion_name:
        assertion_body = (
            f"Assertion:    {escape(info.assertion_name)}\n"
            f"Passed:       {info.assertion_passed}\n"
            f"Findings:     {json.dumps(info.assertion_findings, default=str)[:500] if info.assertion_findings else '---'}"
        )
        console.print(
            Panel(
                assertion_body,
                title="[bold yellow]Assertion Details[/bold yellow]",
                border_style="yellow",
            )
        )

    # AI details
    if info.ai_confidence is not None:
        conf_style = (
            "green"
            if info.ai_confidence >= 0.7
            else "yellow"
            if info.ai_confidence >= 0.5
            else "red"
        )
        ai_body = (
            f"Model:        {info.ai_model or '---'}\n"
            f"Confidence:   [{conf_style}]{info.ai_confidence:.2f}[/{conf_style}]\n"
            f"Assessment:\n{escape(info.ai_assessment or '(none)')[:1000]}"
        )
        console.print(
            Panel(
                ai_body, title="[bold magenta]AI Assessment[/bold magenta]", border_style="magenta"
            )
        )

    # Prompt context
    console.print(
        Panel(
            json.dumps(info.prompt_context, indent=2, default=str),
            title="[bold dim]Reconstructed Prompt Context[/bold dim]",
            border_style="dim",
        )
    )

    # Remediation
    if info.remediation_summary:
        console.print(
            Panel(
                escape(info.remediation_summary),
                title="[bold green]Remediation Summary[/bold green]",
                border_style="green",
            )
        )


@devtools_group.command("compare")
@click.argument("id1")
@click.argument("id2")
def devtools_compare(id1: str, id2: str) -> None:
    """Compare two AI assessments side-by-side.

    ID1: UUID or prefix of the first control result.
    ID2: UUID or prefix of the second control result.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.ai.devtools import AIDevTools

    init_db()
    with get_session() as session:
        tools = AIDevTools(session)
        comparison = tools.compare_assessments(id1, id2)

    if comparison is None:
        _error(f"One or both control results not found: '{id1}', '{id2}'.")

    # Header
    console.print("\n[bold]Assessment Comparison[/bold]")
    console.print(
        f"  Same framework: {'yes' if comparison.same_framework else '[yellow]no[/yellow]'}"
    )
    console.print(
        f"  Same control:   {'yes' if comparison.same_control else '[yellow]no[/yellow]'}"
    )
    console.print(f"  Same model:     {'yes' if comparison.same_model else '[yellow]no[/yellow]'}")
    if comparison.confidence_delta is not None:
        delta_style = "green" if comparison.confidence_delta >= 0 else "red"
        console.print(
            f"  Confidence delta: [{delta_style}]{comparison.confidence_delta:+.2f}[/{delta_style}]"
        )

    # Side-by-side table
    table = Table(title="Side-by-Side Comparison")
    table.add_column("Field", style="cyan")
    table.add_column(f"Left ({comparison.left.control_result_id[:8]})")
    table.add_column(f"Right ({comparison.right.control_result_id[:8]})")

    table.add_row("Framework", comparison.left.framework, comparison.right.framework)
    table.add_row("Control ID", comparison.left.control_id, comparison.right.control_id)
    table.add_row("Status", comparison.left.status, comparison.right.status)
    table.add_row("Severity", comparison.left.severity, comparison.right.severity)
    table.add_row("Assessor", comparison.left.assessor, comparison.right.assessor)
    table.add_row(
        "AI Confidence",
        f"{comparison.left.ai_confidence:.2f}"
        if comparison.left.ai_confidence is not None
        else "N/A",
        f"{comparison.right.ai_confidence:.2f}"
        if comparison.right.ai_confidence is not None
        else "N/A",
    )
    table.add_row(
        "AI Model",
        comparison.left.ai_model or "N/A",
        comparison.right.ai_model or "N/A",
    )
    table.add_row(
        "Assessed At",
        str(comparison.left.assessed_at)[:19] if comparison.left.assessed_at else "---",
        str(comparison.right.assessed_at)[:19] if comparison.right.assessed_at else "---",
    )
    console.print(table)

    # Differences
    console.print(
        Panel(
            "\n".join(f"  - {escape(d)}" for d in comparison.differences),
            title="[bold yellow]Differences[/bold yellow]",
            border_style="yellow",
        )
    )

    # AI assessment text comparison
    if comparison.left.ai_assessment or comparison.right.ai_assessment:
        left_text = (comparison.left.ai_assessment or "(none)")[:500]
        right_text = (comparison.right.ai_assessment or "(none)")[:500]
        console.print(
            Panel(
                escape(left_text),
                title=f"[dim]Left AI Assessment ({comparison.left.control_result_id[:8]})[/dim]",
                border_style="dim",
            )
        )
        console.print(
            Panel(
                escape(right_text),
                title=f"[dim]Right AI Assessment ({comparison.right.control_result_id[:8]})[/dim]",
                border_style="dim",
            )
        )


@devtools_group.command("confidence")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def devtools_confidence(framework: str | None) -> None:
    """Show AI confidence score distribution with outlier detection."""
    from warlock.db.engine import get_session, init_db
    from warlock.ai.devtools import AIDevTools

    init_db()
    with get_session() as session:
        tools = AIDevTools(session)
        analysis = tools.confidence_analysis(framework)

    if analysis.ai_assessed_count == 0:
        console.print("[dim]No AI-assessed control results found.[/dim]")
        return

    # Summary
    console.print("\n[bold]Confidence Analysis[/bold]" + (f" -- {framework}" if framework else ""))
    console.print(f"  Total control results:  {analysis.total_assessments}")
    console.print(f"  AI-assessed:            {analysis.ai_assessed_count}")
    console.print(f"  Mean confidence:        {analysis.mean_confidence:.4f}")
    console.print(f"  Median confidence:      {analysis.median_confidence:.4f}")
    console.print(f"  Std deviation:          {analysis.std_deviation:.4f}")
    console.print(
        f"  Range:                  {analysis.min_confidence:.4f} - {analysis.max_confidence:.4f}"
    )

    # Distribution histogram
    table = Table(title="Confidence Distribution")
    table.add_column("Range", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")
    table.add_column("Histogram", max_width=30)

    max_count = max((b.count for b in analysis.distribution), default=1)
    for bucket in analysis.distribution:
        bar_len = int(bucket.count / max_count * 25) if max_count > 0 else 0
        bar = "#" * bar_len
        style = (
            "green" if bucket.range_low >= 0.7 else "yellow" if bucket.range_low >= 0.4 else "red"
        )
        table.add_row(
            f"{bucket.range_low:.1f}-{bucket.range_high:.1f}",
            str(bucket.count),
            f"{bucket.percentage:.1f}%",
            f"[{style}]{bar}[/{style}]",
        )
    console.print(table)

    # Outliers
    if analysis.outliers_low:
        console.print("\n[yellow]Low-confidence outliers (below mean - 2*std):[/yellow]")
        out_table = Table(title="Outliers")
        out_table.add_column("ID", style="dim", max_width=8)
        out_table.add_column("Framework")
        out_table.add_column("Control")
        out_table.add_column("Confidence", justify="right")
        out_table.add_column("Status")
        out_table.add_column("Model")

        for o in analysis.outliers_low:
            out_table.add_row(
                o.control_result_id[:8],
                o.framework,
                o.control_id,
                f"[red]{o.ai_confidence:.2f}[/red]" if o.ai_confidence is not None else "N/A",
                o.status,
                o.ai_model or "N/A",
            )
        console.print(out_table)
    else:
        console.print("[dim]No low-confidence outliers detected.[/dim]")


# ---------------------------------------------------------------------------
# forecast-risk
# ---------------------------------------------------------------------------


@ai_ops.command("forecast-risk")
@click.option("--framework", "-f", required=True, help="Framework to forecast")
@click.option("--months", "-m", default=3, help="Forecast horizon in months (1-12)")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI narrative")
def forecast_risk(framework: str, months: int, use_ai: bool) -> None:
    """Risk prediction using historical posture data with linear regression.

    Uses PostureSnapshot scores to compute a trend line and project
    future compliance posture for the specified framework.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import PostureSnapshot

    init_db()
    months = max(1, min(12, months))

    with get_session() as session:
        snapshots = (
            session.query(PostureSnapshot)
            .filter(PostureSnapshot.framework == framework)
            .order_by(PostureSnapshot.snapshot_date.asc())
            .limit(1000)
            .all()
        )

    if not snapshots:
        console.print(f"[dim]No posture snapshots found for framework '{escape(framework)}'.[/dim]")
        return

    # Extract time series: (days_since_first, posture_score)
    from warlock.utils import ensure_aware as _ea

    first_date = _ea(snapshots[0].snapshot_date)
    data_points: list[tuple[float, float]] = []
    for s in snapshots:
        snap_date = _ea(s.snapshot_date)
        if snap_date is None or first_date is None:
            continue
        days = (snap_date - first_date).total_seconds() / 86400.0
        data_points.append((days, float(s.posture_score)))

    if len(data_points) < 2:
        console.print("[dim]Insufficient data points for regression (need at least 2).[/dim]")
        return

    # Simple linear regression: y = mx + b
    n = len(data_points)
    sum_x = sum(p[0] for p in data_points)
    sum_y = sum(p[1] for p in data_points)
    sum_xy = sum(p[0] * p[1] for p in data_points)
    sum_x2 = sum(p[0] ** 2 for p in data_points)

    denom = n * sum_x2 - sum_x**2
    if abs(denom) < 1e-10:
        console.print("[dim]Insufficient variance in data for regression.[/dim]")
        return

    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n

    # R-squared
    mean_y = sum_y / n
    ss_tot = sum((p[1] - mean_y) ** 2 for p in data_points)
    ss_res = sum((p[1] - (slope * p[0] + intercept)) ** 2 for p in data_points)
    r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0

    # Current and forecast values
    last_day = data_points[-1][0]
    current_score = slope * last_day + intercept
    forecast_days = months * 30
    forecast_score = slope * (last_day + forecast_days) + intercept
    forecast_score = max(0.0, min(100.0, forecast_score))

    # Trend direction
    if slope > 0.1:
        trend = "[green]improving[/green]"
        trend_label = "improving"
    elif slope < -0.1:
        trend = "[red]declining[/red]"
        trend_label = "declining"
    else:
        trend = "[dim]stable[/dim]"
        trend_label = "stable"

    # Display results
    console.print(f"\n[bold]Risk Forecast: {escape(framework)}[/bold]")
    console.print(f"  Data points:       {n}")
    console.print(f"  Time span:         {data_points[-1][0]:.0f} days")
    console.print(f"  Trend:             {trend} ({slope:+.3f} score/day)")
    console.print(f"  R-squared:         {r_squared:.4f}")
    console.print(f"  Current score:     {current_score:.1f}")
    console.print(f"  Forecast ({months}mo):   {forecast_score:.1f}")

    # Monthly projections table
    table = Table(title=f"Monthly Score Projections ({framework})")
    table.add_column("Month", style="cyan")
    table.add_column("Projected Score", justify="right")
    table.add_column("Risk Level")

    for m in range(1, months + 1):
        proj_score = slope * (last_day + m * 30) + intercept
        proj_score = max(0.0, min(100.0, proj_score))
        risk = (
            "[green]low[/green]"
            if proj_score >= 80
            else "[yellow]medium[/yellow]"
            if proj_score >= 60
            else "[red]high[/red]"
            if proj_score >= 40
            else "[red bold]critical[/red bold]"
        )
        table.add_row(f"+{m}", f"{proj_score:.1f}", risk)
    console.print(table)

    # Risk assessment
    risk_level = (
        "low"
        if forecast_score >= 80
        else "medium"
        if forecast_score >= 60
        else "high"
        if forecast_score >= 40
        else "critical"
    )
    risk_style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green"}.get(
        risk_level, ""
    )
    console.print(
        Panel(
            f"Projected risk level at +{months} months: [{risk_style}]{risk_level.upper()}[/{risk_style}]\n"
            f"Trend: {trend_label} at {abs(slope):.3f} score points/day\n"
            f"Model fit (R-squared): {r_squared:.4f}"
            + (
                "\n\n[yellow]Warning: R-squared < 0.5 indicates weak model fit. "
                "Forecast reliability is low.[/yellow]"
                if r_squared < 0.5
                else ""
            ),
            title="[bold]Risk Assessment[/bold]",
            border_style="cyan",
        )
    )

    if not _check_ai_available(use_ai):
        return

    _run_ai(
        "risk_narrative",
        {
            "framework": framework,
            "data_points": n,
            "current_score": round(current_score, 1),
            "forecast_score": round(forecast_score, 1),
            "forecast_months": months,
            "slope": round(slope, 4),
            "r_squared": round(r_squared, 4),
            "trend": trend_label,
            "risk_level": risk_level,
            "question": (
                f"The {framework} compliance posture score is projected to reach "
                f"{forecast_score:.1f} in {months} months (current: {current_score:.1f}, "
                f"trend: {trend_label}). Provide a risk narrative explaining what this means, "
                "what factors likely drive this trend, and recommend specific actions to "
                "improve the trajectory."
            ),
        },
        f"Risk Forecast: {framework}",
    )
