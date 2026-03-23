"""AI-assisted GRC commands.

Triage, crosswalk, policy drafting, evidence sufficiency, and maturity
benchmarking -- each powered by the unified AI service with graceful
fallback when no provider is configured.

Every command with ``--ai`` also supports ``--ask`` for interactive
follow-up via the AI REPL.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import click
from rich.panel import Panel
from rich.table import Table

from warlock.cli import (
    _ai_repl,
    _check_ai_available,
    _error,
    _parse_ai_response,
    cli,
    console,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_style(severity: str | None) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get((severity or "").lower(), "")


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


def _maybe_ask(ask: bool, entity_type: str, entity_id: str, entity_data: dict) -> None:
    """Launch the AI REPL if --ask was provided."""
    if not ask:
        return
    from warlock.ai.service import get_ai_service
    from warlock.ai.types import ConversationContext

    svc = get_ai_service()
    if not svc.is_available():
        console.print(
            "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
        )
        return

    session_id = uuid.uuid4().hex
    ctx = ConversationContext(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_data=entity_data,
        session_id=session_id,
    )
    _ai_repl(svc, session_id, ctx, f"{entity_type} {entity_id}")


# ---------------------------------------------------------------------------
# AI-001: triage-ai
# ---------------------------------------------------------------------------


@cli.command("triage-ai")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=30, help="Findings to consider")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI triage analysis")
@click.option("--ask", is_flag=True, default=False, help="Interactive AI follow-up")
def triage_ai(framework: str | None, limit: int, use_ai: bool, ask: bool) -> None:
    """AI-assisted triage: severity adjustment, false positive detection, grouping.

    \b
    Gathers open, high-severity findings and uses AI to:
    - Suggest severity adjustments based on context
    - Detect likely false positives
    - Group related findings for batch remediation

    Examples:
        warlock triage-ai --ai                     # AI triage of top findings
        warlock triage-ai -f soc2 --ai --ask       # SOC 2 triage with follow-up
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlMapping, Finding

    init_db()
    with get_session() as session:
        q = session.query(Finding).order_by(Finding.observed_at.desc())
        if framework:
            mapped_ids = (
                session.query(ControlMapping.finding_id)
                .filter(ControlMapping.framework == framework)
                .subquery()
            )
            q = q.filter(Finding.id.in_(session.query(mapped_ids)))
        rows = q.limit(limit).all()

    if not rows:
        console.print("[dim]No findings found for triage.[/dim]")
        return

    # Show summary table
    table = Table(title=f"Findings for triage ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title", max_width=45)
    table.add_column("Severity")
    table.add_column("Source", style="cyan")
    table.add_column("Observed", style="dim")

    sev_counts: dict[str, int] = {}
    finding_data = []
    for r in rows:
        sty = _severity_style(r.severity)
        table.add_row(
            r.id[:8],
            (r.title or "")[:45],
            f"[{sty}]{r.severity}[/]",
            r.source,
            r.observed_at.strftime("%Y-%m-%d") if r.observed_at else "\u2014",
        )
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
        finding_data.append({
            "id": r.id[:8],
            "title": (r.title or "")[:80],
            "severity": r.severity,
            "source": r.source,
            "observation_type": r.observation_type,
            "resource_type": r.resource_type,
        })
    console.print(table)

    # Severity distribution
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in sev_counts:
            sty = _severity_style(sev)
            console.print(f"  [{sty}]{sev}: {sev_counts[sev]}[/]", end="  ")
    console.print()

    if not _check_ai_available(use_ai):
        _maybe_ask(ask, "triage", framework or "all", {"findings": finding_data})
        return

    _run_ai(
        "issue_triage",
        {
            "framework": framework or "all",
            "finding_count": len(finding_data),
            "severity_distribution": sev_counts,
            "findings": finding_data[:15],
            "question": (
                "Triage these findings. For each, suggest: "
                "(1) severity adjustment if warranted, "
                "(2) false positive likelihood (high/medium/low), "
                "(3) grouping with related findings for batch remediation. "
                "Prioritize the list by actual risk impact."
            ),
        },
        "Finding Triage",
    )

    _maybe_ask(ask, "triage", framework or "all", {"findings": finding_data})


# ---------------------------------------------------------------------------
# AI-002: crosswalk-ai
# ---------------------------------------------------------------------------


@cli.command("crosswalk-ai")
@click.option("--source", "source_fw", required=True, help="Source framework (e.g. nist_800_53)")
@click.option("--target", "target_fw", required=True, help="Target framework (e.g. soc2)")
@click.option("--limit", "-n", default=20, help="Max mappings to show")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI crosswalk suggestions")
@click.option("--ask", is_flag=True, default=False, help="Interactive AI follow-up")
def crosswalk_ai(
    source_fw: str, target_fw: str, limit: int, use_ai: bool, ask: bool
) -> None:
    """AI-suggested control mappings between two frameworks.

    \b
    Uses existing control results and AI analysis to suggest how controls
    in the source framework map to controls in the target framework.

    Examples:
        warlock crosswalk-ai --source nist_800_53 --target soc2 --ai
        warlock crosswalk-ai --source iso_27001 --target nist_800_53 --ai --ask
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        source_controls = (
            session.query(
                ControlResult.control_id,
                ControlResult.status,
            )
            .filter(ControlResult.framework == source_fw)
            .distinct()
            .limit(limit)
            .all()
        )
        target_controls = (
            session.query(
                ControlResult.control_id,
                ControlResult.status,
            )
            .filter(ControlResult.framework == target_fw)
            .distinct()
            .limit(limit)
            .all()
        )

    if not source_controls:
        _error(f"No controls found for source framework '{source_fw}'.")
    if not target_controls:
        _error(f"No controls found for target framework '{target_fw}'.")

    # Show both frameworks
    table = Table(title=f"Crosswalk: {source_fw} \u2192 {target_fw}")
    table.add_column(f"{source_fw} Control", style="cyan")
    table.add_column("Status")
    table.add_column(f"{target_fw} Control", style="magenta")
    table.add_column("Status")

    source_data = []
    target_data = []
    max_rows = max(len(source_controls), len(target_controls))
    for i in range(min(max_rows, limit)):
        sc = source_controls[i] if i < len(source_controls) else None
        tc = target_controls[i] if i < len(target_controls) else None
        table.add_row(
            sc.control_id if sc else "\u2014",
            sc.status if sc else "\u2014",
            tc.control_id if tc else "\u2014",
            tc.status if tc else "\u2014",
        )
        if sc:
            source_data.append({"control_id": sc.control_id, "status": sc.status})
        if tc:
            target_data.append({"control_id": tc.control_id, "status": tc.status})

    console.print(table)
    console.print(
        f"\n[dim]{source_fw}: {len(source_controls)} controls  |  "
        f"{target_fw}: {len(target_controls)} controls[/dim]"
    )

    crosswalk_data = {
        "source_framework": source_fw,
        "target_framework": target_fw,
        "source_controls": source_data,
        "target_controls": target_data,
    }

    if not _check_ai_available(use_ai):
        _maybe_ask(ask, "crosswalk", f"{source_fw}-to-{target_fw}", crosswalk_data)
        return

    _run_ai(
        "governance_analysis",
        {
            **crosswalk_data,
            "question": (
                f"Map controls from {source_fw} to {target_fw}. "
                "For each source control, suggest the most likely target control(s) "
                "based on control intent and scope. Indicate confidence (high/medium/low) "
                "for each mapping. Note any source controls with no clear target equivalent."
            ),
        },
        f"Crosswalk: {source_fw} \u2192 {target_fw}",
    )

    _maybe_ask(ask, "crosswalk", f"{source_fw}-to-{target_fw}", crosswalk_data)


# ---------------------------------------------------------------------------
# AI-003: policy-draft
# ---------------------------------------------------------------------------


@cli.command("policy-draft")
@click.option("--control-family", required=True, help="Control family (e.g. AC, SC, AU)")
@click.option("--framework", "-f", default="nist_800_53", help="Framework (default: nist_800_53)")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI policy generation")
@click.option("--ask", is_flag=True, default=False, help="Interactive AI follow-up")
def policy_draft(control_family: str, framework: str, use_ai: bool, ask: bool) -> None:
    """Generate a policy template based on control requirements.

    \b
    Gathers all controls in a control family and their current status,
    then uses AI to draft a policy document covering those controls.

    Examples:
        warlock policy-draft --control-family AC --ai
        warlock policy-draft --control-family SC -f nist_800_53 --ai --ask
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id.startswith(control_family),
            )
            .order_by(ControlResult.control_id)
            .all()
        )

    if not results:
        console.print(
            f"[dim]No control results for family '{control_family}' in {framework}.[/dim]"
        )
        return

    # Summarize controls
    controls: dict[str, dict] = {}
    for r in results:
        if r.control_id not in controls:
            controls[r.control_id] = {
                "control_id": r.control_id,
                "statuses": [],
                "assessors": set(),
            }
        controls[r.control_id]["statuses"].append(r.status)
        if r.assessor:
            controls[r.control_id]["assessors"].add(r.assessor)

    table = Table(title=f"Control Family {control_family} in {framework}")
    table.add_column("Control ID", style="cyan")
    table.add_column("Results", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-Compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")

    control_data = []
    for cid, info in sorted(controls.items()):
        statuses = info["statuses"]
        compliant = statuses.count("compliant")
        non_compliant = statuses.count("non_compliant")
        partial = statuses.count("partial")
        table.add_row(
            cid,
            str(len(statuses)),
            str(compliant),
            str(non_compliant),
            str(partial),
        )
        control_data.append({
            "control_id": cid,
            "total_results": len(statuses),
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
        })

    console.print(table)
    console.print(f"\n[dim]{len(controls)} controls in family {control_family}[/dim]")

    draft_context = {
        "control_family": control_family,
        "framework": framework,
        "controls": control_data,
    }

    if not _check_ai_available(use_ai):
        _maybe_ask(ask, "policy_draft", f"{framework}/{control_family}", draft_context)
        return

    _run_ai(
        "policy_review",
        {
            **draft_context,
            "question": (
                f"Draft a security policy document for the {control_family} control family "
                f"under the {framework} framework. Include:\n"
                "1. Policy title and purpose statement\n"
                "2. Scope and applicability\n"
                "3. Policy statements for each control in the family\n"
                "4. Roles and responsibilities\n"
                "5. Compliance requirements and enforcement\n"
                "6. Review cycle and revision history placeholder\n"
                "Format as a professional policy template."
            ),
        },
        f"Policy Draft: {control_family} ({framework})",
    )

    _maybe_ask(ask, "policy_draft", f"{framework}/{control_family}", draft_context)


# ---------------------------------------------------------------------------
# AI-004: sufficiency-ai
# ---------------------------------------------------------------------------


@cli.command("sufficiency-ai")
@click.option("--framework", "-f", required=True, help="Framework to evaluate (e.g. soc2)")
@click.option("--limit", "-n", default=30, help="Max controls to analyze")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI sufficiency analysis")
@click.option("--ask", is_flag=True, default=False, help="Interactive AI follow-up")
def sufficiency_ai(framework: str, limit: int, use_ai: bool, ask: bool) -> None:
    """AI explains why evidence is insufficient for each control.

    \b
    Finds controls that are non-compliant or partial, gathers their
    evidence, and uses AI to explain what is missing and how to fix it.

    Examples:
        warlock sufficiency-ai -f soc2 --ai
        warlock sufficiency-ai -f nist_800_53 --ai --ask
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    init_db()
    with get_session() as session:
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.status.in_(["non_compliant", "partial", "not_assessed"]),
            )
            .order_by(ControlResult.control_id)
            .limit(limit)
            .all()
        )

    if not results:
        console.print(
            f"[green]All controls in {framework} are compliant or risk-accepted. "
            f"No insufficiency to analyze.[/green]"
        )
        return

    # Group by control
    controls: dict[str, dict] = {}
    for r in results:
        if r.control_id not in controls:
            controls[r.control_id] = {
                "control_id": r.control_id,
                "statuses": [],
                "evidence_counts": [],
                "remediation_summaries": [],
            }
        controls[r.control_id]["statuses"].append(r.status)
        controls[r.control_id]["evidence_counts"].append(len(r.evidence_ids or []))
        if r.remediation_summary:
            controls[r.control_id]["remediation_summaries"].append(
                r.remediation_summary[:200]
            )

    table = Table(title=f"Insufficient Evidence: {framework}")
    table.add_column("Control ID", style="cyan")
    table.add_column("Status")
    table.add_column("Results", justify="right")
    table.add_column("Avg Evidence", justify="right")

    status_styles = {
        "non_compliant": "red",
        "partial": "yellow",
        "not_assessed": "dim",
    }
    control_data = []
    for cid, info in sorted(controls.items()):
        primary_status = max(set(info["statuses"]), key=info["statuses"].count)
        avg_ev = sum(info["evidence_counts"]) / len(info["evidence_counts"]) if info["evidence_counts"] else 0
        st_sty = status_styles.get(primary_status, "")
        table.add_row(
            cid,
            f"[{st_sty}]{primary_status}[/]",
            str(len(info["statuses"])),
            f"{avg_ev:.1f}",
        )
        control_data.append({
            "control_id": cid,
            "primary_status": primary_status,
            "result_count": len(info["statuses"]),
            "avg_evidence": round(avg_ev, 1),
            "remediation_hints": info["remediation_summaries"][:2],
        })

    console.print(table)
    console.print(f"\n[dim]{len(controls)} controls with insufficient evidence[/dim]")

    sufficiency_context = {
        "framework": framework,
        "controls": control_data,
    }

    if not _check_ai_available(use_ai):
        _maybe_ask(ask, "sufficiency", framework, sufficiency_context)
        return

    _run_ai(
        "evidence_evaluation",
        {
            **sufficiency_context,
            "question": (
                f"For each control in the {framework} framework that has insufficient evidence, "
                "explain:\n"
                "1. What evidence is typically required for this control\n"
                "2. Why the current evidence appears insufficient\n"
                "3. Specific steps to gather the missing evidence\n"
                "4. Priority (high/medium/low) for addressing this gap\n"
                "Be specific about what auditors expect to see."
            ),
        },
        f"Evidence Sufficiency: {framework}",
    )

    _maybe_ask(ask, "sufficiency", framework, sufficiency_context)


# ---------------------------------------------------------------------------
# AI-005: benchmark-ai
# ---------------------------------------------------------------------------


@cli.command("benchmark-ai")
@click.option("--framework", "-f", required=True, help="Framework to benchmark (e.g. soc2)")
@click.option("--ai", "use_ai", is_flag=True, default=False, help="Enable AI maturity analysis")
@click.option("--ask", is_flag=True, default=False, help="Interactive AI follow-up")
def benchmark_ai(framework: str, use_ai: bool, ask: bool) -> None:
    """AI analyzes maturity profile and suggests highest-ROI next steps.

    \b
    Computes a maturity profile for the given framework based on control
    results, then uses AI to analyze maturity gaps and recommend the
    highest-ROI improvements.

    Examples:
        warlock benchmark-ai -f soc2 --ai
        warlock benchmark-ai -f nist_800_53 --ai --ask
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                ControlResult.control_id,
                ControlResult.status,
                func.count(ControlResult.id).label("cnt"),
            )
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.control_id, ControlResult.status)
            .all()
        )

    if not rows:
        _error(f"No control results for framework '{framework}'.")

    # Build maturity profile
    control_status: dict[str, dict[str, int]] = {}
    for r in rows:
        if r.control_id not in control_status:
            control_status[r.control_id] = {}
        control_status[r.control_id][r.status] = int(r.cnt)

    total_controls = len(control_status)
    fully_compliant = sum(
        1 for cs in control_status.values()
        if cs.get("compliant", 0) > 0 and cs.get("non_compliant", 0) == 0
    )
    non_compliant = sum(
        1 for cs in control_status.values() if cs.get("non_compliant", 0) > 0
    )
    partial = total_controls - fully_compliant - non_compliant

    maturity_pct = (fully_compliant / total_controls * 100) if total_controls else 0
    maturity_level = (
        "Advanced" if maturity_pct >= 80
        else "Established" if maturity_pct >= 60
        else "Developing" if maturity_pct >= 40
        else "Initial" if maturity_pct >= 20
        else "Ad-hoc"
    )
    maturity_color = (
        "green" if maturity_pct >= 80
        else "cyan" if maturity_pct >= 60
        else "yellow" if maturity_pct >= 40
        else "red" if maturity_pct >= 20
        else "red bold"
    )

    console.print(
        Panel(
            f"Framework:      [bold cyan]{framework}[/bold cyan]\n"
            f"Total controls: [bold]{total_controls}[/bold]\n\n"
            f"  [green]Fully compliant:  {fully_compliant}[/green]  "
            f"({fully_compliant / total_controls * 100:.0f}%)\n"
            f"  [yellow]Partial:          {partial}[/yellow]  "
            f"({partial / total_controls * 100:.0f}%)\n"
            f"  [red]Non-compliant:    {non_compliant}[/red]  "
            f"({non_compliant / total_controls * 100:.0f}%)\n\n"
            f"Maturity:       [{maturity_color}]{maturity_level} ({maturity_pct:.0f}%)[/]",
            title="[bold]Maturity Benchmark[/bold]",
            border_style="blue",
        )
    )

    # Find highest-gap control families
    family_gaps: dict[str, int] = {}
    for cid, cs in control_status.items():
        family = cid.split("-")[0] if "-" in cid else cid.split(".")[0] if "." in cid else cid[:2]
        if cs.get("non_compliant", 0) > 0:
            family_gaps[family] = family_gaps.get(family, 0) + 1

    if family_gaps:
        gap_table = Table(title="Control Family Gaps")
        gap_table.add_column("Family", style="cyan")
        gap_table.add_column("Non-Compliant Controls", justify="right", style="red")
        for fam, cnt in sorted(family_gaps.items(), key=lambda x: -x[1])[:10]:
            gap_table.add_row(fam, str(cnt))
        console.print(gap_table)

    benchmark_data = {
        "framework": framework,
        "total_controls": total_controls,
        "fully_compliant": fully_compliant,
        "non_compliant": non_compliant,
        "partial": partial,
        "maturity_pct": round(maturity_pct, 1),
        "maturity_level": maturity_level,
        "family_gaps": dict(sorted(family_gaps.items(), key=lambda x: -x[1])[:10]),
    }

    if not _check_ai_available(use_ai):
        _maybe_ask(ask, "benchmark", framework, benchmark_data)
        return

    _run_ai(
        "governance_analysis",
        {
            **benchmark_data,
            "question": (
                f"Analyze this {framework} maturity profile. Based on the compliance data:\n"
                "1. Assess the overall maturity posture\n"
                "2. Identify the highest-ROI improvements (which control families "
                "   would move the needle most if addressed)\n"
                "3. Suggest a phased remediation roadmap (30/60/90 day)\n"
                "4. Note any quick wins that could improve the score immediately\n"
                "5. Compare this profile to typical industry benchmarks"
            ),
        },
        f"Maturity Benchmark: {framework}",
    )

    _maybe_ask(ask, "benchmark", framework, benchmark_data)
