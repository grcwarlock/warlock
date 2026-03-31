"""Remediation tracking commands.

5-stage state machine: open -> assigned -> in_progress -> verification -> closed.
Follows the same CLI patterns as incidents_cmd.py.
"""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, _parse_ai_response, cli, console

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

_VALID_STATUSES = ["open", "assigned", "in_progress", "verification", "closed"]

_TRANSITIONS: dict[str, list[str]] = {
    "open": ["assigned"],
    "assigned": ["in_progress", "open"],
    "in_progress": ["verification", "assigned"],
    "verification": ["closed", "in_progress"],
    "closed": [],
}

_STATUS_STYLES: dict[str, str] = {
    "open": "yellow",
    "assigned": "cyan",
    "in_progress": "blue",
    "verification": "magenta",
    "closed": "green",
}

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("remediate", invoke_without_command=True)
@click.option("--ai/--no-ai", "use_ai", default=None, help="AI-powered remediation suggestions")
@click.option(
    "--ask",
    default=None,
    help="Ask AI a question about remediations (e.g. 'What should I prioritize?')",
)
@click.pass_context
def remediate(ctx: click.Context, use_ai: bool | None, ask: str | None) -> None:
    """Remediation lifecycle management (create, assign, track, close)."""
    if ctx.invoked_subcommand is not None:
        return

    # Default: show open remediations summary
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Remediation

    init_db()
    with get_session() as session:
        all_rem = session.query(Remediation).all()

    if not all_rem:
        console.print("[dim]No remediations found.[/dim]")
        if ask is not None or use_ai:
            console.print("[yellow]No remediation data available for AI analysis.[/yellow]")
        return

    counts: dict[str, int] = {}
    for r in all_rem:
        counts[r.status] = counts.get(r.status, 0) + 1

    table = Table(title=f"Remediations ({len(all_rem)})")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    for st in _VALID_STATUSES:
        count = counts.get(st, 0)
        if count > 0:
            style = _STATUS_STYLES.get(st, "")
            table.add_row(f"[{style}]{st}[/]", str(count))
    console.print(table)

    # --ask: AI question about remediations
    if ask is not None:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import ConversationContext

        svc = get_ai_service()
        if not svc.is_available():
            console.print(
                "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
            )
            return

        rem_data = [
            {
                "title": r.title,
                "status": r.status,
                "framework": r.framework,
                "control_id": r.control_id,
            }
            for r in all_rem
        ]
        ai_ctx = ConversationContext(
            domain="remediation",
            entity_type="remediation",
            entity_data={"remediations": rem_data, "count": len(all_rem)},
        )
        resp = svc.ask(ask, context=ai_ctx)
        console.print()
        _parse_ai_response(resp)

    # --ai: AI-enhanced summary
    elif use_ai:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import ConversationContext

        svc = get_ai_service()
        if not svc.is_available():
            console.print(
                "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
            )
            return

        rem_data = [
            {
                "title": r.title,
                "status": r.status,
                "framework": r.framework,
                "control_id": r.control_id,
            }
            for r in all_rem
        ]
        ai_ctx = ConversationContext(
            domain="remediation",
            entity_type="remediation",
            entity_data={"remediations": rem_data, "count": len(all_rem)},
        )
        resp = svc.analyze("remediation_summary", context=ai_ctx)
        console.print()
        _parse_ai_response(resp)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@remediate.command("list")
@click.option(
    "--status",
    default=None,
    type=click.Choice(_VALID_STATUSES + [""]),
    help="Filter by status",
)
@click.option("--assigned-to", default=None, help="Filter by assignee")
@click.option("--limit", "-n", default=50, help="Max results")
def remediate_list(status: str | None, assigned_to: str | None, limit: int) -> None:
    """List remediations with optional filters."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Remediation

    init_db()
    with get_session() as session:
        q = session.query(Remediation)
        if status:
            q = q.filter(Remediation.status == status)
        if assigned_to:
            q = q.filter(Remediation.assigned_to == assigned_to)
        rows = q.order_by(Remediation.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No remediations found.[/dim]")
        return

    table = Table(title=f"Remediations ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title", max_width=45)
    table.add_column("Status")
    table.add_column("Assigned", style="dim")
    table.add_column("Framework", style="dim")
    table.add_column("Control", style="dim")
    table.add_column("Created", style="dim")

    for r in rows:
        st_style = _STATUS_STYLES.get(r.status, "")
        created = r.created_at.strftime("%Y-%m-%d") if r.created_at else "\u2014"
        table.add_row(
            r.id[:8],
            escape(r.title[:45] if r.title else "\u2014"),
            f"[{st_style}]{r.status}[/]",
            escape(r.assigned_to or "\u2014"),
            escape(r.framework or "\u2014"),
            escape(r.control_id or "\u2014"),
            created,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@remediate.command("create")
@click.option("--title", "-t", required=True, help="Remediation title")
@click.option("--finding-id", default=None, help="Finding ID to link")
@click.option("--framework", "-f", default=None, help="Framework name")
@click.option("--control-id", "-c", default=None, help="Control ID")
@click.option("--description", "-d", default=None, help="Description")
def remediate_create(
    title: str,
    finding_id: str | None,
    framework: str | None,
    control_id: str | None,
    description: str | None,
) -> None:
    """Create a new remediation."""
    import uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Remediation

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        rem = Remediation(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            finding_id=finding_id,
            framework=framework,
            control_id=control_id,
            status="open",
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        session.add(rem)
        session.commit()

        console.print(
            f"[green]Remediation created:[/green] [cyan]{rem.id[:8]}[/cyan] \u2014 {escape(title)}"
        )


# ---------------------------------------------------------------------------
# assign
# ---------------------------------------------------------------------------


@remediate.command("assign")
@click.argument("remediation_id")
@click.option("--to", "assignee", required=True, help="User to assign to")
def remediate_assign(remediation_id: str, assignee: str) -> None:
    """Assign a remediation to a user."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Remediation

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        rem = session.query(Remediation).filter(Remediation.id.startswith(remediation_id)).first()
        if not rem:
            _error(f"Remediation not found: {remediation_id}")

        if "assigned" not in _TRANSITIONS.get(rem.status, []):
            _error(
                f"Cannot assign remediation in status '{rem.status}'. "
                f"Valid transitions: {_TRANSITIONS.get(rem.status, [])}"
            )

        rem.status = "assigned"
        rem.assigned_to = assignee
        rem.assigned_by = actor
        rem.assigned_at = now
        rem.updated_at = now
        session.commit()

    console.print(f"[green]Remediation {remediation_id[:8]} assigned[/green] to {escape(assignee)}")


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------


@remediate.command("start")
@click.argument("remediation_id")
def remediate_start(remediation_id: str) -> None:
    """Start work on a remediation (assigned -> in_progress)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Remediation

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        rem = session.query(Remediation).filter(Remediation.id.startswith(remediation_id)).first()
        if not rem:
            _error(f"Remediation not found: {remediation_id}")

        if "in_progress" not in _TRANSITIONS.get(rem.status, []):
            _error(
                f"Cannot start remediation in status '{rem.status}'. "
                f"Valid transitions: {_TRANSITIONS.get(rem.status, [])}"
            )

        rem.status = "in_progress"
        rem.updated_at = now
        session.commit()

    console.print(f"[green]Remediation {remediation_id[:8]} started[/green] (in_progress)")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@remediate.command("verify")
@click.argument("remediation_id")
def remediate_verify(remediation_id: str) -> None:
    """Submit a remediation for verification (in_progress -> verification)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Remediation

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        rem = session.query(Remediation).filter(Remediation.id.startswith(remediation_id)).first()
        if not rem:
            _error(f"Remediation not found: {remediation_id}")

        if "verification" not in _TRANSITIONS.get(rem.status, []):
            _error(
                f"Cannot verify remediation in status '{rem.status}'. "
                f"Valid transitions: {_TRANSITIONS.get(rem.status, [])}"
            )

        rem.status = "verification"
        rem.updated_at = now
        session.commit()

    console.print(f"[green]Remediation {remediation_id[:8]} submitted for verification[/green]")


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


@remediate.command("close")
@click.argument("remediation_id")
@click.option("--notes", default=None, help="Verification/closure notes")
def remediate_close(remediation_id: str, notes: str | None) -> None:
    """Close a remediation after verification."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Remediation

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        rem = session.query(Remediation).filter(Remediation.id.startswith(remediation_id)).first()
        if not rem:
            _error(f"Remediation not found: {remediation_id}")

        if "closed" not in _TRANSITIONS.get(rem.status, []):
            _error(
                f"Cannot close remediation in status '{rem.status}'. "
                f"Valid transitions: {_TRANSITIONS.get(rem.status, [])}"
            )

        rem.status = "closed"
        rem.closed_at = now
        rem.verified_by = actor
        rem.verified_at = now
        if notes:
            rem.verification_notes = notes
        rem.updated_at = now
        session.commit()

    console.print(f"[green]Remediation {remediation_id[:8]} closed[/green]")
    if notes:
        console.print(f"  Notes: {escape(notes)}")


# ---------------------------------------------------------------------------
# wizard — guided remediation
# ---------------------------------------------------------------------------


@remediate.command("wizard")
@click.argument("finding_id")
@click.option("--complete", is_flag=True, default=False, help="Mark as complete after review")
def remediate_wizard(finding_id: str, complete: bool) -> None:
    """Guided remediation wizard for a finding."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.workflows.remediation_wizard import RemediationWizard

    init_db()
    actor = _get_actor()

    with get_session() as session:
        wizard = RemediationWizard()

        try:
            result = wizard.generate_steps(session, finding_id)
        except ValueError as e:
            _error(str(e))
            return  # unreachable

        console.print(
            Panel(
                f"[bold]{escape(result['finding_title'])}[/bold]",
                title="Remediation Wizard",
                border_style="cyan",
            )
        )

        for step_data in result["steps"]:
            step_num = step_data["step"]
            title = step_data["title"]
            content = step_data["content"]

            console.print(f"\n[cyan bold]Step {step_num}: {title}[/cyan bold]")

            if isinstance(content, dict):
                for key, val in content.items():
                    if isinstance(val, list):
                        console.print(f"  [dim]{key}:[/dim]")
                        for item in val:
                            if isinstance(item, dict):
                                parts = [f"{k}={v}" for k, v in item.items() if v]
                                console.print(f"    - {escape(', '.join(parts))}")
                            else:
                                console.print(f"    - {escape(str(item))}")
                    elif val and val != "N/A":
                        console.print(f"  [dim]{key}:[/dim] {escape(str(val))}")
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        fw = item.get("framework", "")
                        ctrl = item.get("control_id", "")
                        label = f"{fw}/{ctrl}" if fw else "General"
                        console.print(f"  [cyan]{escape(label)}[/cyan]")
                        if item.get("summary"):
                            console.print(f"    {escape(item['summary'])}")
                        for rs in item.get("remediation_steps", []):
                            console.print(f"    - {escape(str(rs))}")
                    else:
                        console.print(f"  {escape(str(item))}")

        if complete:
            try:
                comp = wizard.mark_complete(session, finding_id, actor=actor)
                console.print(
                    f"\n[green bold]Remediation marked complete[/green bold] "
                    f"(remediation {comp['remediation_id'][:8]})"
                )
            except ValueError as e:
                _error(str(e))
        else:
            console.print("\n[dim]Run with --complete to mark this remediation as done.[/dim]")


# ---------------------------------------------------------------------------
# auto — automated remediation with dry-run default
# ---------------------------------------------------------------------------


@remediate.command("auto")
@click.option("-f", "--framework", default=None, help="Scope to a framework")
@click.option(
    "--execute",
    is_flag=True,
    default=False,
    help="Actually execute actions (default is dry-run)",
)
@click.option("--limit", "-n", default=100, help="Max findings to scan")
def remediate_auto(framework: str | None, execute: bool, limit: int) -> None:
    """Run automated remediation (dry-run by default).

    Scans high/critical findings and maps them to remediation actions:
    s3_public_access, security_group_open, unencrypted_volume, mfa_disabled,
    logging_disabled.

    Pass --execute to actually apply changes. Without it, only a preview
    plan is shown.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.auto_remediate import AutoRemediator

    init_db()
    dry_run = not execute
    remediator = AutoRemediator(dry_run=dry_run)

    with get_session() as session:
        plan = remediator.build_plan(session, framework=framework, limit=limit)

    mode_label = "[yellow]DRY RUN[/yellow]" if dry_run else "[red bold]LIVE[/red bold]"
    console.print(f"\n[bold]Auto-Remediation Plan[/bold] ({mode_label})")

    if not plan.actions:
        console.print("[dim]No actionable findings found.[/dim]")
        console.print(
            f"[dim]Scanned {plan.summary.get('total_findings_scanned', 0)} "
            f"high/critical findings.[/dim]"
        )
        return

    table = Table(title=f"Remediation Actions ({len(plan.actions)})")
    table.add_column("Action", style="cyan")
    table.add_column("Resource", max_width=30)
    table.add_column("Description", max_width=50)
    table.add_column("Result")

    for action in plan.actions:
        table.add_row(
            action.action_type,
            escape(action.resource_id[:30]),
            escape(action.description[:50]),
            escape(action.result[:60]) if action.result else "\u2014",
        )

    console.print(table)

    summary = plan.summary
    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  Findings scanned: {summary.get('total_findings_scanned', 0)}")
    console.print(f"  Actions planned:  {summary.get('actions_planned', 0)}")
    for atype, count in summary.get("action_counts", {}).items():
        console.print(f"    {atype}: {count}")

    if dry_run:
        console.print("\n[dim]This was a dry run. Pass --execute to apply changes.[/dim]")
