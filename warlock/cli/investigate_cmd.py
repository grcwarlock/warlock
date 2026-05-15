"""Interactive investigation workflows for GRC practitioners.

Chains findings -> controls -> remediation -> action in a single guided flow
so practitioners can drill from a high-level posture summary down to an
actionable remediation step without typing five separate commands.

Commands registered on the CLI:
    warlock investigate source <name>       -- by connector source
    warlock investigate framework <name>   -- by framework
    warlock investigate finding <id>       -- deep finding detail
    warlock investigate control <id>       -- deep control detail
    warlock triage                         -- critical-first triage queue
    warlock audit-prep <framework>         -- pre-audit readiness checklist
    warlock daily                          -- practitioner morning summary
    warlock remediate-guided <id>          -- guided remediation for a finding or control
"""

from __future__ import annotations

import uuid as _uuid_mod
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import click
from rich.panel import Panel
from rich.table import Table

from warlock.cli import (
    _check_ai_available,
    _error,
    _get_actor,
    _parse_ai_response,
    cli,
    console,
)

# ---------------------------------------------------------------------------
# Severity ordering helpers
# ---------------------------------------------------------------------------

_SEV_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_STYLE: dict[str, str] = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
    "info": "dim",
}


def _sev_style(sev: str) -> str:
    return _SEV_STYLE.get((sev or "").lower(), "")


def _sev_rank(sev: str) -> int:
    return _SEV_ORDER.get((sev or "").lower(), 99)


def _prompt(message: str, non_interactive: bool, default: str = "") -> str:
    """Prompt in interactive mode; return default in non-interactive mode."""
    if non_interactive:
        return default
    try:
        value = input(f"{message} ").strip()
        return value
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")
        raise SystemExit(0)


def _confirm(message: str, non_interactive: bool, default: bool = False) -> bool:
    """Yes/no confirmation in interactive mode; return default otherwise."""
    if non_interactive:
        return default
    try:
        raw = input(f"{message} [y/N] ").strip().lower()
        return raw in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")
        raise SystemExit(0)


# ---------------------------------------------------------------------------
# Shared DB helpers
# ---------------------------------------------------------------------------


def _counts_by_sev(rows: list[Any]) -> dict[str, int]:
    """Count rows by .severity attribute."""
    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        counts[(r.severity or "info").lower()] += 1
    return dict(counts)


def _nc_results_for_source(session: Any, source: str) -> list[Any]:
    """Non-compliant ControlResults whose linked Finding came from *source*."""

    from warlock.db.models import ControlResult, Finding

    return (
        session.query(ControlResult)
        .join(Finding, Finding.id == ControlResult.finding_id)
        .filter(
            Finding.source.ilike(source),
            ControlResult.status == "non_compliant",
        )
        .all()
    )


def _nc_results_for_framework(session: Any, framework: str) -> list[Any]:
    from warlock.db.models import ControlResult

    return (
        session.query(ControlResult)
        .filter(
            ControlResult.framework.ilike(framework),
            ControlResult.status == "non_compliant",
        )
        .all()
    )


def _create_poam_for_result(session: Any, result: Any, actor: str) -> Any:
    """Create a draft POA&M for a ControlResult, skipping if one already exists."""
    from warlock.workflows.poam import POAMManager

    mgr = POAMManager()
    poam = mgr.auto_create_from_result(session, result)
    if poam:
        session.commit()
    return poam


def _create_exception_for_control(session: Any, framework: str, control_id: str, actor: str) -> str:
    """Create a minimal policy exception (PolicyOverride + AuditEntry) and return its ID."""
    from warlock.db.models import PolicyOverride

    override = PolicyOverride(
        name=f"Exception: {framework}/{control_id}",
        description=f"Policy exception auto-created via investigate workflow for control {control_id}.",
        policy_rego=(
            f"# Auto-generated exception for {framework}/{control_id}\n"
            f"# Review and refine before activating.\n"
            f"package warlock.exception\n\nexception {{ true }}\n"
        ),
        is_active=False,  # Not active until reviewed
        created_by=actor,
    )
    session.add(override)
    session.flush()

    # SEC-C4: canonical hash-chained trail.
    from warlock.db.audit import AuditTrail

    expiry = (datetime.now(timezone.utc) + timedelta(days=90)).date().isoformat()

    AuditTrail(session).record(
        action="policy_exception",
        entity_type="exception",
        entity_id=override.id,
        actor=actor,
        metadata={
            "framework": framework,
            "control_id": control_id,
            "status": "active",
            "expiry": expiry,
            "justification": "Created via investigate workflow — pending review",
            "approved_by": actor,
        },
    )
    session.commit()
    return override.id


# ---------------------------------------------------------------------------
# Action loop — shared by investigate source, framework, control
# ---------------------------------------------------------------------------


def _action_loop(
    session: Any,
    results: list[Any],
    framework: str | None,
    control_id: str | None,
    non_interactive: bool,
    actor: str,
    *,
    ai_enabled: bool = False,
) -> None:
    """Present the [r]emediate/[p]oam/[e]xception/[s]kip/[q]uit prompt."""
    if non_interactive:
        # Non-interactive: just dump remediation steps for every result
        for r in results:
            if r.remediation_summary:
                console.print(f"[bold]{r.framework}/{r.control_id}[/bold]: {r.remediation_summary}")
            if r.remediation_steps:
                for step in r.remediation_steps:
                    console.print(f"  - {step}")
        return

    while True:
        console.print("\n[bold]Actions:[/bold] [r]emediate  [p]oam  [e]xception  [s]kip  [q]uit")
        choice = _prompt("Choice:", non_interactive).lower()

        if choice in ("q", "quit"):
            break
        elif choice in ("s", "skip"):
            console.print("[dim]Skipped.[/dim]")
            break
        elif choice in ("r", "remediate"):
            _show_remediation_steps(results, ai_enabled=ai_enabled, session=session)
        elif choice in ("p", "poam"):
            created = 0
            for r in results:
                poam = _create_poam_for_result(session, r, actor)
                if poam:
                    console.print(
                        f"[green]POA&M created:[/green] {poam.id[:8]} "
                        f"({r.framework}/{r.control_id})"
                    )
                    created += 1
            if not created:
                console.print("[dim]No new POA&Ms needed — open ones already exist.[/dim]")
        elif choice in ("e", "exception"):
            fw = framework or (results[0].framework if results else "unknown")
            ctrl = control_id or (results[0].control_id if results else "unknown")
            exc_id = _create_exception_for_control(session, fw, ctrl, actor)
            console.print(
                f"[green]Exception created (inactive, pending review):[/green] {exc_id[:8]}"
            )
        else:
            console.print("[yellow]Unknown choice. Enter r/p/e/s/q.[/yellow]")


def _show_remediation_steps(
    results: list[Any],
    *,
    ai_enabled: bool = False,
    session: Any = None,
) -> None:
    """Print remediation steps for a list of ControlResults."""
    for r in results:
        console.print(f"\n[bold cyan]{r.framework}/{r.control_id}[/bold cyan]")
        if r.remediation_summary:
            console.print(f"  {r.remediation_summary}")
        if r.remediation_steps:
            for i, step in enumerate(r.remediation_steps, 1):
                console.print(f"  {i}. {step}")
        if r.console_path:
            console.print(f"  Console: {r.console_path}")
        if not r.remediation_summary and not r.remediation_steps:
            # Fall back to remediation KB
            try:
                from warlock.assessors.remediation_loader import get_remediation

                guidance = get_remediation(r.framework, r.control_id)
                if guidance:
                    console.print(f"  {guidance.get('summary', '')}")
                    for i, step in enumerate(guidance.get("remediation_steps", []), 1):
                        console.print(f"  {i}. {step}")
            except Exception:
                console.print("  [dim]No remediation guidance available.[/dim]")

    if ai_enabled:
        try:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask

            svc = get_ai_service()
            if svc.is_task_enabled(AITask.REMEDIATION_GUIDANCE):
                ctx: dict = {
                    "framework": results[0].framework if results else "",
                    "control_id": results[0].control_id if results else "",
                    "count": len(results),
                }
                ai_result = svc.reason(AITask.REMEDIATION_GUIDANCE, context=ctx)
                if ai_result.ai_used:
                    console.print("\n[bold]AI Guidance:[/bold]")
                    value = ai_result.value
                    if isinstance(value, dict):
                        console.print(value.get("guidance") or value.get("narrative") or str(value))
                    else:
                        console.print(str(value) if value else "")
        except Exception as exc:
            console.print(f"[dim]AI guidance unavailable: {exc.__class__.__name__}[/dim]")


# ---------------------------------------------------------------------------
# warlock investigate
# ---------------------------------------------------------------------------


@cli.group("investigate", invoke_without_command=True)
@click.pass_context
def investigate(ctx: click.Context) -> None:
    """Interactive investigation workflows -- drill into findings, controls, and compliance."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@investigate.command("source")
@click.argument("source_name")
@click.option("--ai", "use_ai", is_flag=True, help="Enable AI-enhanced analysis")
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
def investigate_source(source_name: str, use_ai: bool, non_interactive: bool) -> None:
    """Interactive investigation of all non-compliant findings for SOURCE_NAME.

    Example: warlock investigate source aws
    """
    from warlock.db.engine import get_session, init_db

    ai_enabled = _check_ai_available(use_ai if use_ai else None)
    actor = _get_actor()
    init_db()

    with get_session() as session:
        results = _nc_results_for_source(session, source_name)

        if not results:
            console.print(
                f"[dim]No non-compliant findings for source '[bold]{source_name}[/bold]'.[/dim]"
            )
            return

        # Step 2: Summary table grouped by framework
        by_framework: dict[str, list[Any]] = defaultdict(list)
        for r in results:
            by_framework[r.framework].append(r)

        table = Table(title=f"Non-compliant controls -- source: {source_name}")
        table.add_column("Framework", style="cyan")
        table.add_column("Non-compliant", justify="right")
        table.add_column("Critical", justify="right", style="red bold")
        table.add_column("High", justify="right", style="red")
        table.add_column("Medium", justify="right", style="yellow")
        table.add_column("Low", justify="right", style="dim")

        for fw, fw_results in sorted(by_framework.items()):
            counts = _counts_by_sev(fw_results)
            table.add_row(
                fw,
                str(len(fw_results)),
                str(counts.get("critical", 0)),
                str(counts.get("high", 0)),
                str(counts.get("medium", 0)),
                str(counts.get("low", 0)),
            )

        console.print(table)

        # Step 3: Select framework
        fw_choices = sorted(by_framework.keys())
        console.print(f"\nFrameworks: {', '.join(fw_choices)} (or 'all')")
        chosen_fw = _prompt("Select a framework to drill into:", non_interactive, default="all")
        if chosen_fw.lower() == "all":
            drill_results = results
            active_fw = None
        else:
            if chosen_fw not in by_framework:
                console.print(f"[yellow]Framework '{chosen_fw}' not found. Using all.[/yellow]")
                drill_results = results
                active_fw = None
            else:
                drill_results = by_framework[chosen_fw]
                active_fw = chosen_fw

        # Step 4: Show non-compliant controls
        by_control: dict[str, list[Any]] = defaultdict(list)
        for r in drill_results:
            by_control[f"{r.framework}/{r.control_id}"].append(r)

        ctrl_table = Table(title="Non-compliant controls")
        ctrl_table.add_column("Control", style="cyan")
        ctrl_table.add_column("Severity")
        ctrl_table.add_column("Findings", justify="right")

        for ctrl_key in sorted(by_control.keys()):
            ctrl_rows = by_control[ctrl_key]
            worst = sorted(ctrl_rows, key=lambda x: _sev_rank(x.severity))[0]
            sty = _sev_style(worst.severity)
            ctrl_table.add_row(
                ctrl_key,
                f"[{sty}]{worst.severity}[/{sty}]" if sty else worst.severity,
                str(len(ctrl_rows)),
            )

        console.print(ctrl_table)

        # Step 5: Select control
        ctrl_choices = sorted(by_control.keys())
        chosen_ctrl = _prompt(
            f"Select a control to investigate (e.g., {ctrl_choices[0] if ctrl_choices else 'AC-2'}):",
            non_interactive,
            default=ctrl_choices[0] if ctrl_choices else "",
        )

        # Match partial: "AC-2" or "nist_800_53/AC-2"
        matched_key = None
        for k in ctrl_choices:
            if (
                k == chosen_ctrl
                or k.endswith(f"/{chosen_ctrl}")
                or k.lower() == chosen_ctrl.lower()
            ):
                matched_key = k
                break
        if not matched_key and ctrl_choices:
            matched_key = ctrl_choices[0]

        selected_results = by_control.get(matched_key or "", drill_results[:5])

        # Step 6: Show detail
        if matched_key:
            fw_part, ctrl_part = (
                matched_key.split("/", 1) if "/" in matched_key else (active_fw, matched_key)
            )
            _show_control_detail_panel(session, fw_part, ctrl_part, selected_results)

        # Step 7: Action loop
        _action_loop(
            session,
            selected_results,
            framework=active_fw,
            control_id=ctrl_part if matched_key else None,
            non_interactive=non_interactive,
            actor=actor,
            ai_enabled=ai_enabled,
        )


@investigate.command("framework")
@click.argument("framework_name")
@click.option("--ai", "use_ai", is_flag=True, help="Enable AI-enhanced analysis")
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
def investigate_framework(framework_name: str, use_ai: bool, non_interactive: bool) -> None:
    """Interactive compliance investigation for a specific FRAMEWORK_NAME.

    Example: warlock investigate framework soc2
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult

    ai_enabled = _check_ai_available(use_ai if use_ai else None)
    actor = _get_actor()
    init_db()

    with get_session() as session:
        # Step 1: Compliance posture
        all_results = (
            session.query(ControlResult).filter(ControlResult.framework.ilike(framework_name)).all()
        )
        nc_results = [r for r in all_results if r.status == "non_compliant"]
        compliant = [r for r in all_results if r.status == "compliant"]

        total = len(all_results)
        if total == 0:
            console.print(
                f"[dim]No control results found for framework '[bold]{framework_name}[/bold]'. "
                f"Run 'warlock collect' first.[/dim]"
            )
            return

        pct = int(len(compliant) / total * 100) if total else 0
        console.print(
            Panel(
                f"[bold]{framework_name.upper()}[/bold] Compliance Posture\n\n"
                f"Total controls assessed: {total}\n"
                f"Compliant: [green]{len(compliant)}[/green]  "
                f"Non-compliant: [red]{len(nc_results)}[/red]  "
                f"Score: [{'green' if pct >= 80 else 'yellow' if pct >= 60 else 'red'}]{pct}%[/]",
                border_style="cyan",
            )
        )

        if not nc_results:
            console.print("[green]All controls compliant![/green]")
            return

        # Step 2: Group by control family (prefix before '-')
        by_family: dict[str, list[Any]] = defaultdict(list)
        for r in nc_results:
            family = r.control_id.split("-")[0] if "-" in r.control_id else r.control_id[:3]
            by_family[family].append(r)

        family_table = Table(title="Non-compliant by control family")
        family_table.add_column("Family", style="cyan")
        family_table.add_column("Controls", justify="right")
        family_table.add_column("Critical", justify="right", style="red bold")
        family_table.add_column("High", justify="right", style="red")

        for fam in sorted(by_family.keys()):
            fam_rows = by_family[fam]
            counts = _counts_by_sev(fam_rows)
            family_table.add_row(
                fam,
                str(len(fam_rows)),
                str(counts.get("critical", 0)),
                str(counts.get("high", 0)),
            )

        console.print(family_table)

        # Step 3: Select family
        fam_choices = sorted(by_family.keys())
        chosen_fam = _prompt(
            f"Select a control family to drill into ({', '.join(fam_choices)}):",
            non_interactive,
            default=fam_choices[0] if fam_choices else "",
        )
        if chosen_fam not in by_family:
            console.print(f"[yellow]Family '{chosen_fam}' not found. Using first.[/yellow]")
            chosen_fam = fam_choices[0] if fam_choices else ""

        fam_results = by_family.get(chosen_fam, nc_results[:10])

        # Step 4: Show individual controls in the family
        ctrl_table = Table(title=f"Family: {chosen_fam}")
        ctrl_table.add_column("Control", style="cyan")
        ctrl_table.add_column("Severity")
        ctrl_table.add_column("Assessment")

        by_ctrl: dict[str, list[Any]] = defaultdict(list)
        for r in fam_results:
            by_ctrl[r.control_id].append(r)

        for ctrl_id in sorted(by_ctrl.keys()):
            ctrl_rows = by_ctrl[ctrl_id]
            worst = sorted(ctrl_rows, key=lambda x: _sev_rank(x.severity))[0]
            sty = _sev_style(worst.severity)
            ctrl_table.add_row(
                ctrl_id,
                f"[{sty}]{worst.severity}[/{sty}]" if sty else worst.severity,
                worst.assessor or "",
            )

        console.print(ctrl_table)

        # Step 5: Select control
        ctrl_choices = sorted(by_ctrl.keys())
        chosen_ctrl = _prompt(
            f"Select a control (e.g., {ctrl_choices[0] if ctrl_choices else ''}):",
            non_interactive,
            default=ctrl_choices[0] if ctrl_choices else "",
        )
        selected_results = by_ctrl.get(chosen_ctrl, fam_results[:3])
        actual_ctrl = (
            chosen_ctrl if chosen_ctrl in by_ctrl else (ctrl_choices[0] if ctrl_choices else "")
        )

        _show_control_detail_panel(session, framework_name, actual_ctrl, selected_results)

        _action_loop(
            session,
            selected_results,
            framework=framework_name,
            control_id=actual_ctrl,
            non_interactive=non_interactive,
            actor=actor,
            ai_enabled=ai_enabled,
        )


@investigate.command("finding")
@click.argument("finding_id")
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
@click.option("--ai", "use_ai", is_flag=True, help="AI explain this finding")
def investigate_finding(finding_id: str, non_interactive: bool, use_ai: bool) -> None:
    """Deep investigation of a specific finding by FINDING_ID (or prefix).

    Shows blast radius across frameworks/controls and offers triage actions.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry, ControlMapping, Finding, Issue

    ai_enabled = _check_ai_available(use_ai if use_ai else None)
    _ = _get_actor()  # reserved for future audit entries on suppress/escalate actions
    init_db()

    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id.startswith(finding_id)).first()
        if not finding:
            _error(f"Finding not found: {finding_id}. Use 'warlock findings list' to find IDs.")

        # Step 1: Detail panel
        observed = (
            finding.observed_at.strftime("%Y-%m-%d %H:%M UTC") if finding.observed_at else "unknown"
        )
        sty = _sev_style(finding.severity)
        console.print(
            Panel(
                f"[bold]{finding.title}[/bold]\n\n"
                f"Severity: [{sty}]{finding.severity}[/{sty}]  |  "
                f"Source: {finding.source} ({finding.provider})\n"
                f"Resource: {finding.resource_type or ''} {finding.resource_id or ''}\n"
                f"Region: {finding.region or 'n/a'}  |  Observed: {observed}",
                title=f"[bold]Finding[/bold] {finding.id[:8]}",
                border_style="yellow",
            )
        )

        # Step 2: Control mappings
        mappings = (
            session.query(ControlMapping).filter(ControlMapping.finding_id == finding.id).all()
        )
        if mappings:
            map_table = Table(title="Controls this finding maps to")
            map_table.add_column("Framework", style="cyan")
            map_table.add_column("Control", style="cyan")
            map_table.add_column("Family")
            map_table.add_column("Method")
            map_table.add_column("Confidence", justify="right")

            for m in mappings:
                map_table.add_row(
                    m.framework,
                    m.control_id,
                    m.control_family or "",
                    m.mapping_method,
                    f"{m.confidence:.2f}",
                )
            console.print(map_table)

        # Step 3: Blast radius
        frameworks_affected = len({m.framework for m in mappings})
        controls_affected = len(mappings)
        console.print(
            f"\n[bold]Blast radius:[/bold] {frameworks_affected} framework(s), "
            f"{controls_affected} control(s) affected."
        )

        # Step 4: Audit trail (last 5 entries)
        audit_entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_id == finding.id,
                AuditEntry.entity_type == "finding",
            )
            .order_by(AuditEntry.created_at.desc())
            .limit(5)
            .all()
        )
        if audit_entries:
            console.print(f"\n[bold]Audit trail[/bold] (last {len(audit_entries)}):")
            for entry in audit_entries:
                ts = entry.created_at.strftime("%Y-%m-%d %H:%M") if entry.created_at else ""
                console.print(f"  [dim]{ts}[/dim]  {entry.action}  by {entry.actor}")

        if non_interactive:
            return

        # Step 5: Action prompt
        while True:
            console.print(
                "\n[bold]Actions:[/bold] [s]uppress  [l]ink to issue  [e]scalate  "
                "[a]i explain  [q]uit"
            )
            choice = _prompt("Choice:", non_interactive).lower()

            if choice in ("q", "quit"):
                break
            elif choice in ("s", "suppress"):
                console.print(
                    f"[dim]Suppression recorded. Use 'warlock findings suppress {finding.id[:8]}' "
                    f"to persist.[/dim]"
                )
                break
            elif choice in ("l", "link"):
                issue_prefix = _prompt("Issue ID to link (prefix):", non_interactive)
                if issue_prefix:
                    issue = session.query(Issue).filter(Issue.id.startswith(issue_prefix)).first()
                    if issue:
                        if not issue.finding_id:
                            issue.finding_id = finding.id
                            session.commit()
                        console.print(f"[green]Finding linked to issue {issue.id[:8]}.[/green]")
                    else:
                        console.print("[yellow]Issue not found.[/yellow]")
            elif choice in ("e", "escalate"):
                console.print(
                    f"[yellow]Escalation noted. Use 'warlock issues' to create a critical issue "
                    f"referencing finding {finding.id[:8]}.[/yellow]"
                )
            elif choice in ("a", "ai"):
                if not ai_enabled:
                    console.print("[yellow]AI not available (use --ai flag).[/yellow]")
                    continue
                try:
                    from warlock.ai.service import get_ai_service
                    from warlock.ai.types import ConversationContext

                    svc = get_ai_service()
                    session_id = _uuid_mod.uuid4().hex
                    ctx = ConversationContext(
                        entity_type="finding",
                        entity_id=finding.id,
                        entity_data={
                            "title": finding.title,
                            "severity": finding.severity,
                            "source": finding.source,
                            "resource_type": finding.resource_type,
                            "observation_type": finding.observation_type,
                        },
                        session_id=session_id,
                    )
                    result = svc.converse(
                        session_id=session_id,
                        message="Explain this finding and its compliance implications.",
                        context=ctx,
                    )
                    if result.ai_used:
                        console.print(f"\n[bold]AI:[/bold] {_parse_ai_response(result.value)}")
                    else:
                        console.print(f"[yellow]AI unavailable: {result.fallback_reason}[/yellow]")
                except Exception as exc:
                    console.print(f"[yellow]AI error: {exc}[/yellow]")
            else:
                console.print("[yellow]Unknown choice. Enter s/l/e/a/q.[/yellow]")


@investigate.command("control")
@click.argument("control_id")
@click.option("--framework", "-f", default=None, help="Narrow to a specific framework")
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
@click.option("--ai", "use_ai", is_flag=True, help="AI-enhanced analysis")
def investigate_control(
    control_id: str, framework: str | None, non_interactive: bool, use_ai: bool
) -> None:
    """Deep investigation of a specific control by CONTROL_ID (e.g. AC-2).

    Example: warlock investigate control AC-2
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding

    ai_enabled = _check_ai_available(use_ai if use_ai else None)
    actor = _get_actor()
    init_db()

    with get_session() as session:
        q = session.query(ControlResult).filter(ControlResult.control_id.ilike(control_id))
        if framework:
            q = q.filter(ControlResult.framework.ilike(framework))

        all_results = q.order_by(ControlResult.assessed_at.desc()).limit(50).all()

        if not all_results:
            console.print(f"[dim]No control results found for '[bold]{control_id}[/bold]'.[/dim]")
            return

        # Step 1: Detail
        sample = all_results[0]
        nc = [r for r in all_results if r.status == "non_compliant"]
        compliant = [r for r in all_results if r.status == "compliant"]
        status_color = "green" if not nc else "red"

        console.print(
            Panel(
                f"[bold]{sample.framework}/{sample.control_id}[/bold]\n\n"
                f"Status: [{status_color}]{'COMPLIANT' if not nc else 'NON-COMPLIANT'}[/{status_color}]\n"
                f"Total results: {len(all_results)}  "
                f"Compliant: [green]{len(compliant)}[/green]  "
                f"Non-compliant: [red]{len(nc)}[/red]\n"
                f"Last assessed: {sample.assessed_at.strftime('%Y-%m-%d %H:%M UTC') if sample.assessed_at else 'n/a'}",
                title=f"[bold]Control[/bold] {control_id}",
                border_style="cyan",
            )
        )

        # Step 2: Findings mapped to this control
        finding_ids = {r.finding_id for r in all_results if r.finding_id}
        if finding_ids:
            findings = (
                session.query(Finding)
                .filter(Finding.id.in_(finding_ids))
                .order_by(Finding.severity)
                .limit(10)
                .all()
            )
            if findings:
                f_table = Table(title="Findings mapped to this control")
                f_table.add_column("ID", style="dim", max_width=8)
                f_table.add_column("Severity")
                f_table.add_column("Source")
                f_table.add_column("Title", max_width=50)

                for f in findings:
                    sty = _sev_style(f.severity)
                    f_table.add_row(
                        f.id[:8],
                        f"[{sty}]{f.severity}[/{sty}]" if sty else f.severity,
                        f.source,
                        f.title[:50],
                    )
                console.print(f_table)

        # Step 3: Evidence freshness
        if all_results:
            newest = max((r.assessed_at for r in all_results if r.assessed_at), default=None)
            if newest:
                if newest.tzinfo is None:
                    newest = newest.replace(tzinfo=timezone.utc)
                age_hours = (datetime.now(timezone.utc) - newest).total_seconds() / 3600
                if age_hours < 24:
                    freshness = f"[green]Fresh[/green] ({age_hours:.0f}h ago)"
                elif age_hours < 168:
                    freshness = f"[yellow]Aging[/yellow] ({age_hours:.0f}h ago)"
                else:
                    freshness = f"[red]Stale[/red] ({age_hours:.0f}h ago)"
                console.print(f"\n[bold]Evidence status:[/bold] {freshness}")

        # Step 4: Assertion results
        assertions = {r.assertion_name for r in all_results if r.assertion_name}
        if assertions:
            console.print(f"\n[bold]Assertions:[/bold] {', '.join(sorted(assertions))}")

        if non_interactive:
            return

        # Step 5: Action prompt
        while True:
            console.print(
                "\n[bold]Actions:[/bold] [r]emediate  [t]est  [p]oam  [e]vidence request  [q]uit"
            )
            choice = _prompt("Choice:", non_interactive).lower()

            if choice in ("q", "quit"):
                break
            elif choice in ("r", "remediate"):
                _show_remediation_steps(nc or all_results[:3], ai_enabled=ai_enabled)
            elif choice in ("t", "test"):
                console.print(f"[dim]Run: warlock control-tests run --control {control_id}[/dim]")
            elif choice in ("p", "poam"):
                created = 0
                for r in nc or all_results[:1]:
                    poam = _create_poam_for_result(session, r, actor)
                    if poam:
                        console.print(f"[green]POA&M created:[/green] {poam.id[:8]}")
                        created += 1
                if not created:
                    console.print("[dim]No new POA&Ms needed.[/dim]")
            elif choice in ("e", "evidence request"):
                console.print(
                    f"[dim]Run: warlock evidence request --control {control_id} "
                    f"--framework {framework or sample.framework}[/dim]"
                )
            else:
                console.print("[yellow]Unknown choice. Enter r/t/p/e/q.[/yellow]")


def _show_control_detail_panel(
    session: Any, framework: str | None, control_id: str | None, results: list[Any]
) -> None:
    """Print a summary panel for a control + its failing resources."""
    from warlock.db.models import Finding

    if not results:
        return

    sample = results[0]
    finding_ids = [r.finding_id for r in results if r.finding_id]
    findings: list[Any] = []
    if finding_ids:
        findings = session.query(Finding).filter(Finding.id.in_(finding_ids)).limit(10).all()

    fw_label = framework or sample.framework
    ctrl_label = control_id or sample.control_id

    lines = [f"[bold]{fw_label}/{ctrl_label}[/bold]\n"]
    if sample.remediation_summary:
        lines.append(f"Remediation: {sample.remediation_summary}\n")

    if findings:
        lines.append("Failing resources:")
        for f in findings:
            lines.append(
                f"  {f.resource_type or 'resource'}  {f.resource_id or 'unknown'}  "
                f"[dim]{f.region or ''}[/dim]"
            )

    console.print(Panel("\n".join(lines), title="Control detail", border_style="yellow"))


# ---------------------------------------------------------------------------
# warlock triage
# ---------------------------------------------------------------------------


@cli.command("triage")
@click.option(
    "--severity", "-s", default="critical", help="Start severity level (default: critical)"
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
def triage(severity: str, non_interactive: bool) -> None:
    """Interactive finding triage -- work through unreviewed findings by severity.

    Starts with the specified severity (default: critical) and walks through each.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, Issue

    actor = _get_actor()
    init_db()

    sev_order = ["critical", "high", "medium", "low", "info"]
    start_idx = sev_order.index(severity.lower()) if severity.lower() in sev_order else 0

    with get_session() as session:
        # Collect findings without linked issues, ordered by severity
        all_findings = (
            session.query(Finding).order_by(Finding.severity, Finding.observed_at.desc()).all()
        )

        # Filter to findings that have no open issue
        existing_issue_finding_ids = {
            i.finding_id
            for i in session.query(Issue)
            .filter(
                Issue.finding_id.isnot(None),
                Issue.status.notin_(["closed", "verified"]),
            )
            .all()
        }

        unreviewed = [
            f
            for f in all_findings
            if f.id not in existing_issue_finding_ids
            and _sev_rank(f.severity) >= _sev_rank(sev_order[start_idx])
        ]

        # Sort: critical first
        unreviewed.sort(key=lambda f: _sev_rank(f.severity))

        if not unreviewed:
            console.print("[green]No unreviewed findings at this severity level.[/green]")
            return

        console.print(
            f"[bold]Triage queue:[/bold] {len(unreviewed)} unreviewed finding(s) "
            f"(starting at {severity})"
        )

        triaged = 0
        total = len(unreviewed)

        for idx, finding in enumerate(unreviewed):
            console.print(f"\n[dim]--- [{idx + 1}/{total}] ---[/dim]")
            sty = _sev_style(finding.severity)
            observed = finding.observed_at.strftime("%Y-%m-%d") if finding.observed_at else "?"
            console.print(
                Panel(
                    f"[{sty}]{finding.severity.upper()}[/{sty}]  {finding.title}\n\n"
                    f"Source: {finding.source} | Resource: {finding.resource_type} {finding.resource_id or ''}\n"
                    f"Observed: {observed}",
                    title=f"Finding {finding.id[:8]}",
                    border_style="yellow",
                )
            )

            if non_interactive:
                triaged += 1
                continue

            console.print(
                "[bold]Actions:[/bold] [a]ssign to issue  [s]uppress  "
                "[l]ink to existing issue  [n]ext  [q]uit"
            )
            choice = _prompt(f"Triaged {triaged}/{total} -- choice:", non_interactive).lower()

            if choice in ("q", "quit"):
                break
            elif choice in ("n", "next"):
                triaged += 1
                continue
            elif choice in ("s", "suppress"):
                console.print(f"[dim]Suppress noted for {finding.id[:8]}.[/dim]")
                triaged += 1
            elif choice in ("a", "assign"):
                from warlock.db.models import ControlResult
                from warlock.workflows.issues import IssueManager

                # Find any control result for this finding
                cr = (
                    session.query(ControlResult)
                    .filter(ControlResult.finding_id == finding.id)
                    .first()
                )
                if cr:
                    mgr = IssueManager()
                    issue = mgr.create_from_finding(session, finding.id, cr.id, created_by=actor)
                    session.commit()
                    console.print(
                        f"[green]Issue created:[/green] {issue.id[:8]} [{issue.priority}] {issue.title[:60]}"
                    )
                else:
                    console.print(
                        "[yellow]No control result linked -- cannot auto-create issue.[/yellow]"
                    )
                triaged += 1
            elif choice in ("l", "link"):
                issue_prefix = _prompt("Issue ID to link (prefix):", non_interactive)
                if issue_prefix:
                    issue = session.query(Issue).filter(Issue.id.startswith(issue_prefix)).first()
                    if issue:
                        if not issue.finding_id:
                            issue.finding_id = finding.id
                            session.commit()
                        console.print(f"[green]Linked to issue {issue.id[:8]}.[/green]")
                    else:
                        console.print("[yellow]Issue not found.[/yellow]")
                triaged += 1
            else:
                console.print("[yellow]Unknown choice.[/yellow]")

        console.print(
            f"\n[bold]Triage session complete.[/bold] {triaged}/{total} findings reviewed."
        )


# ---------------------------------------------------------------------------
# warlock audit-prep
# ---------------------------------------------------------------------------


@cli.command("audit-prep")
@click.argument("framework")
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
def audit_prep(framework: str, non_interactive: bool) -> None:
    """Interactive audit preparation checklist for FRAMEWORK.

    Example: warlock audit-prep soc2
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        POAM,
        Attestation,
        ControlResult,
        EvidenceRequest,
    )

    _ = _get_actor()  # reserved for future auto-remediation actions
    init_db()

    with get_session() as session:
        # 1. Evidence freshness
        nc_results = _nc_results_for_framework(session, framework)
        stale_threshold = datetime.now(timezone.utc) - timedelta(days=30)
        all_fw_results = (
            session.query(ControlResult).filter(ControlResult.framework.ilike(framework)).all()
        )

        def _aware(dt: datetime | None) -> datetime | None:
            if dt is None:
                return None
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt

        stale = [
            r
            for r in all_fw_results
            if r.assessed_at
            and (_aware(r.assessed_at) or datetime.min.replace(tzinfo=timezone.utc))
            < stale_threshold
        ]

        # 2. Open POA&Ms overdue
        now = datetime.now(timezone.utc)
        overdue_poams = (
            session.query(POAM)
            .filter(
                POAM.framework.ilike(framework),
                POAM.status.in_(["open", "in_progress"]),
                POAM.scheduled_completion.isnot(None),
                POAM.scheduled_completion < now,
            )
            .all()
        )

        # 3. Attestation coverage
        all_attests = (
            session.query(Attestation).filter(Attestation.framework.ilike(framework)).all()
        )
        approved_attests = [a for a in all_attests if a.status == "approved"]
        total_controls = len({r.control_id for r in all_fw_results})
        attest_pct = int(len(approved_attests) / total_controls * 100) if total_controls else 0

        # 4. Pending evidence requests
        pending_evidence = (
            session.query(EvidenceRequest)
            .filter(
                EvidenceRequest.framework.ilike(framework),
                EvidenceRequest.status.in_(["requested", "in_progress"]),
            )
            .all()
        )

        # 5. Control test coverage (placeholder — control_tests table if available)
        # tested_pct would come from ControlTest results when implemented

        # Compute readiness score (0-100)
        score = 100
        if stale:
            score -= min(30, len(stale) * 2)
        if overdue_poams:
            score -= min(20, len(overdue_poams) * 5)
        if attest_pct < 80:
            score -= int((80 - attest_pct) * 0.25)
        if pending_evidence:
            score -= min(10, len(pending_evidence) * 2)
        score = max(0, score)

        score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        console.print(
            Panel(
                f"[bold]{framework.upper()}[/bold] Audit Readiness\n\n"
                f"Readiness score: [{score_color}]{score}/100[/{score_color}]",
                border_style="cyan",
            )
        )

        # Checklist table
        check_table = Table(title="Audit preparation checklist")
        check_table.add_column("Item")
        check_table.add_column("Status")
        check_table.add_column("Detail")

        def _check(ok: bool) -> str:
            return "[green]PASS[/green]" if ok else "[red]FAIL[/red]"

        check_table.add_row(
            "Evidence freshness",
            _check(not stale),
            f"{len(stale)} stale control(s)" if stale else "All fresh",
        )
        check_table.add_row(
            "Open POA&Ms",
            _check(not overdue_poams),
            f"{len(overdue_poams)} overdue" if overdue_poams else "None overdue",
        )
        check_table.add_row(
            "Attestation coverage",
            _check(attest_pct >= 80),
            f"{attest_pct}% signed ({len(approved_attests)}/{total_controls})",
        )
        check_table.add_row(
            "Pending evidence requests",
            _check(not pending_evidence),
            f"{len(pending_evidence)} pending" if pending_evidence else "None pending",
        )
        check_table.add_row(
            "Non-compliant controls",
            _check(not nc_results),
            f"{len(nc_results)} non-compliant" if nc_results else "All compliant",
        )

        console.print(check_table)

        if non_interactive:
            return

        # Interactive auto-remediate loop
        failing_items = []
        if stale:
            failing_items.append(("Evidence freshness", f"{len(stale)} stale controls", "evidence"))
        if overdue_poams:
            failing_items.append(("Open POA&Ms", f"{len(overdue_poams)} overdue", "poams"))
        if attest_pct < 80:
            failing_items.append(("Attestation coverage", f"{attest_pct}% signed", "attestations"))
        if pending_evidence:
            failing_items.append(
                ("Pending evidence", f"{len(pending_evidence)} pending", "evidence_requests")
            )

        for item_name, item_detail, item_type in failing_items:
            console.print(f"\n[yellow]{item_name}[/yellow]: {item_detail}")
            if _confirm("Address this item?", non_interactive, default=False):
                if item_type == "poams":
                    console.print("[dim]Run: warlock poams --framework {framework} --overdue[/dim]")
                elif item_type == "evidence":
                    console.print("[dim]Run: warlock collect to refresh evidence.[/dim]")
                elif item_type == "attestations":
                    console.print(
                        f"[dim]Run: warlock attestations create --framework {framework}[/dim]"
                    )
                elif item_type == "evidence_requests":
                    console.print("[dim]Run: warlock evidence requests --status requested[/dim]")


# ---------------------------------------------------------------------------
# warlock daily
# ---------------------------------------------------------------------------


@cli.command("daily")
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
def daily(non_interactive: bool) -> None:
    """Daily GRC practitioner morning summary and workflow launcher."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        POAM,
        Finding,
        Issue,
    )

    init_db()

    with get_session() as session:
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        next_week = datetime.now(timezone.utc) + timedelta(days=7)

        # New findings since yesterday
        new_findings = (
            session.query(Finding)
            .filter(Finding.ingested_at >= yesterday)
            .order_by(Finding.severity)
            .all()
        )

        # Overdue items: POA&Ms
        overdue_poams = (
            session.query(POAM)
            .filter(
                POAM.status.in_(["open", "in_progress"]),
                POAM.scheduled_completion < datetime.now(timezone.utc),
            )
            .all()
        )

        # Open issues
        open_issues = (
            session.query(Issue).filter(Issue.status.in_(["open", "assigned", "in_progress"])).all()
        )

        # Upcoming deadlines (POA&Ms due in next 7 days)
        upcoming = (
            session.query(POAM)
            .filter(
                POAM.status.in_(["open", "in_progress"]),
                POAM.scheduled_completion >= datetime.now(timezone.utc),
                POAM.scheduled_completion <= next_week,
            )
            .all()
        )

        new_counts = _counts_by_sev(new_findings)
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        console.print(
            Panel(
                f"[bold]Good morning! GRC Summary for {today_str}[/bold]\n\n"
                f"New findings (24h): "
                f"[red bold]{new_counts.get('critical', 0)} critical[/red bold]  "
                f"[red]{new_counts.get('high', 0)} high[/red]  "
                f"[yellow]{new_counts.get('medium', 0)} medium[/yellow]  "
                f"[dim]{new_counts.get('low', 0)} low[/dim]\n\n"
                f"Overdue POA&Ms: [{'red' if overdue_poams else 'green'}]{len(overdue_poams)}[/]\n"
                f"Open issues: {len(open_issues)}\n"
                f"Upcoming deadlines (7 days): {len(upcoming)}",
                title="[bold cyan]Warlock Daily Briefing[/bold cyan]",
                border_style="cyan",
            )
        )

        if upcoming:
            deadline_table = Table(title="Upcoming deadlines (next 7 days)")
            deadline_table.add_column("POA&M", max_width=8, style="dim")
            deadline_table.add_column("Framework")
            deadline_table.add_column("Control")
            deadline_table.add_column("Due")
            deadline_table.add_column("Status")

            for p in upcoming:
                due = p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else ""
                deadline_table.add_row(p.id[:8], p.framework, p.control_id, due, p.status)
            console.print(deadline_table)

        if non_interactive:
            return

        console.print(
            "\n[bold]What would you like to focus on?[/bold]  "
            "[f]indings  [i]ssues  [o]verdue  [a]udit-prep  [q]uit"
        )
        choice = _prompt("Choice:", non_interactive).lower()

        if choice in ("f", "findings"):
            ctx = click.get_current_context()
            ctx.invoke(triage, severity="critical", non_interactive=False)
        elif choice in ("i", "issues"):
            console.print("[dim]Run: warlock issues[/dim]")
        elif choice in ("o", "overdue"):
            console.print("[dim]Run: warlock poams --overdue[/dim]")
        elif choice in ("a", "audit-prep"):
            fw = _prompt("Framework name:", non_interactive)
            if fw:
                ctx = click.get_current_context()
                ctx.invoke(audit_prep, framework=fw, non_interactive=False)
        elif choice in ("q", "quit"):
            pass
        else:
            console.print("[dim]No action taken.[/dim]")


# ---------------------------------------------------------------------------
# warlock remediate-guided
# ---------------------------------------------------------------------------


@cli.command("remediate-guided")
@click.argument("item_id")
@click.option(
    "--ai", "use_ai", is_flag=True, help="AI-enhanced remediation with env-specific commands"
)
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Output without prompts (for piping/scripting)",
)
def remediate_guided(item_id: str, use_ai: bool, non_interactive: bool) -> None:
    """Guided remediation workflow for a finding ID or control ID.

    Identifies the item, shows remediation steps (with optional AI enhancement),
    then prompts to update status.

    Example:
        warlock remediate-guided <finding-id-prefix>
        warlock remediate-guided AC-2 --ai
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult, Finding, Issue

    ai_enabled = _check_ai_available(use_ai if use_ai else None)
    actor = _get_actor()
    init_db()

    with get_session() as session:
        # Identify: try Finding first, then ControlResult by control_id
        finding: Any = None
        results: list[Any] = []
        label = item_id

        # 1. Try as finding UUID prefix
        finding = session.query(Finding).filter(Finding.id.startswith(item_id)).first()

        if finding:
            label = f"Finding {finding.id[:8]}: {finding.title[:60]}"
            results = (
                session.query(ControlResult)
                .filter(
                    ControlResult.finding_id == finding.id,
                    ControlResult.status == "non_compliant",
                )
                .all()
            )
        else:
            # 2. Try as control_id
            results = (
                session.query(ControlResult)
                .filter(
                    ControlResult.control_id.ilike(item_id),
                    ControlResult.status == "non_compliant",
                )
                .order_by(ControlResult.assessed_at.desc())
                .limit(10)
                .all()
            )
            if results:
                label = f"Control {results[0].framework}/{results[0].control_id}"
            else:
                _error(
                    f"Not found: '{item_id}'. Provide a finding ID prefix or a control ID like AC-2."
                )

        # Step 2: Show the issue
        sty = _sev_style(finding.severity if finding else (results[0].severity if results else ""))
        sev = finding.severity if finding else (results[0].severity if results else "unknown")

        console.print(
            Panel(
                f"[bold]{label}[/bold]\n\n"
                f"Severity: [{sty}]{sev}[/{sty}]\n"
                f"Non-compliant results: {len(results)}",
                title="[bold]Guided Remediation[/bold]",
                border_style="yellow",
            )
        )

        # Step 3: Show remediation steps
        if results:
            _show_remediation_steps(results, ai_enabled=ai_enabled, session=session)
        elif finding:
            console.print(
                "[dim]No non-compliant results found for this finding. "
                "It may have already been remediated.[/dim]"
            )

        if non_interactive:
            return

        # Step 4: Prompt for next action
        while True:
            console.print(
                "\n[bold]Mark as:[/bold] [i]n progress  [r]esolved  [c]reate POA&M  [q]uit"
            )
            choice = _prompt("Choice:", non_interactive).lower()

            if choice in ("q", "quit"):
                break
            elif choice in ("i", "in_progress", "in progress"):
                # Find linked issue and transition
                issue: Any = None
                if finding:
                    issue = (
                        session.query(Issue)
                        .filter(
                            Issue.finding_id == finding.id,
                            Issue.status.notin_(["closed", "verified"]),
                        )
                        .first()
                    )
                if issue:
                    from warlock.workflows.issues import IssueManager

                    mgr = IssueManager()
                    try:
                        mgr.transition(session, issue.id, "in_progress", actor=actor)
                        console.print(f"[green]Issue {issue.id[:8]} -> in_progress[/green]")
                    except ValueError as exc:
                        console.print(f"[yellow]{exc}[/yellow]")
                else:
                    console.print(
                        "[dim]No linked issue found. Use 'warlock issues' to manage.[/dim]"
                    )
            elif choice in ("r", "resolved"):
                issue = None
                if finding:
                    issue = (
                        session.query(Issue)
                        .filter(
                            Issue.finding_id == finding.id,
                            Issue.status.notin_(["closed", "verified"]),
                        )
                        .first()
                    )
                if issue:
                    from warlock.workflows.issues import IssueManager

                    mgr = IssueManager()
                    try:
                        mgr.transition(session, issue.id, "remediated", actor=actor)
                        console.print(f"[green]Issue {issue.id[:8]} -> remediated[/green]")
                    except ValueError as exc:
                        console.print(f"[yellow]{exc}[/yellow]")
                else:
                    console.print("[dim]No linked issue found.[/dim]")
                break
            elif choice in ("c", "create poam", "create_poam"):
                created = 0
                for r in results:
                    poam = _create_poam_for_result(session, r, actor)
                    if poam:
                        console.print(
                            f"[green]POA&M created:[/green] {poam.id[:8]} ({r.framework}/{r.control_id})"
                        )
                        created += 1
                if not created:
                    console.print("[dim]No new POA&Ms needed — open ones already exist.[/dim]")
            else:
                console.print("[yellow]Unknown choice. Enter i/r/c/q.[/yellow]")
