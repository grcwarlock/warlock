"""Governance commands: issues, issues-auto-create, poams, compensating-controls,
risk-acceptances, remediate, inheritance, dependencies."""

from __future__ import annotations

import os

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import (
    cli,
    console,
    _error,
    _get_actor,
    _parse_ai_response,
    _ai_repl,
    _resolve_system_id,
)


@cli.group("issues", invoke_without_command=True)
@click.option(
    "--status", "-s", default=None, help="Filter by status (open, assigned, in_progress, etc.)"
)
@click.option(
    "--priority", "-p", default=None, help="Filter by priority (critical, high, medium, low)"
)
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--system", default=None, help="Filter by system profile ID or acronym")
@click.option("--assigned-to", default=None, help="Filter by assignee")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default=None)
@click.option("--export", "export_path", default=None, help="Export to file (json/csv)")
@click.option(
    "--ask",
    default=None,
    help="Ask AI a question about the listed issues (e.g. 'What should I fix first?')",
)
@click.pass_context
def issues(
    ctx: click.Context,
    status: str | None,
    priority: str | None,
    framework: str | None,
    system: str | None,
    assigned_to: str | None,
    limit: int,
    fmt: str | None,
    export_path: str | None,
    ask: str | None,
) -> None:
    """List and manage compliance issues."""
    if ctx.invoked_subcommand is not None:
        return
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Issue

    init_db()

    with get_session() as session:
        q = session.query(Issue)
        if status:
            q = q.filter(Issue.status == status)
        else:
            # Default: show non-closed issues
            q = q.filter(Issue.status.notin_(["closed", "verified"]))
        if priority:
            q = q.filter(Issue.priority == priority)
        if framework:
            q = q.filter(Issue.framework == framework)
        if system:
            from warlock.db.models import SystemProfile

            sp = (
                session.query(SystemProfile)
                .filter(
                    (SystemProfile.name.ilike(f"%{system}%"))
                    | (SystemProfile.id.like(f"{system}%"))
                    | (SystemProfile.acronym.ilike(system))
                )
                .first()
            )
            if sp and sp.frameworks:
                q = q.filter(Issue.framework.in_(sp.frameworks))
            else:
                console.print(f"[red]System '{system}' not found or has no frameworks.[/red]")
                return
        if assigned_to:
            q = q.filter(Issue.assigned_to == assigned_to)
        q = q.order_by(Issue.created_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No issues found.[/dim]")
        return

    from warlock.cli.output import format_output, get_output_format

    data = [
        {
            "id": i.id[:8],
            "framework": i.framework or "",
            "control_id": i.control_id or "",
            "title": (i.title or "")[:50],
            "status": i.status or "",
            "priority": i.priority or "",
            "assigned_to": i.assigned_to or "",
        }
        for i in rows
    ]

    _COLUMNS = [
        {"key": "id", "header": "ID", "style": "dim", "max_width": "8"},
        {"key": "framework", "header": "Framework", "style": "cyan"},
        {"key": "control_id", "header": "Control", "style": "cyan"},
        {"key": "title", "header": "Title", "max_width": "50"},
        {"key": "status", "header": "Status"},
        {"key": "priority", "header": "Priority"},
        {"key": "assigned_to", "header": "Assigned To", "style": "dim"},
    ]

    format_output(
        data,
        _COLUMNS,
        fmt=get_output_format(ctx, fmt),
        title=f"Issues ({len(rows)})",
        style_map={
            "status": {
                "open": "yellow",
                "assigned": "blue",
                "in_progress": "cyan",
                "remediated": "green",
                "verified": "green bold",
                "closed": "dim",
                "risk_accepted": "magenta",
            },
            "priority": {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            },
        },
        export_path=export_path,
    )

    # --ask: AI question about the listed issues (or REPL if empty)
    if ask is not None:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import ConversationContext

        svc = get_ai_service()
        if not svc.is_available():
            console.print(
                "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
            )
            return

        import uuid

        session_id = uuid.uuid4().hex
        issues_summary = [
            {
                "id": i.id[:8],
                "title": i.title,
                "framework": i.framework,
                "control_id": i.control_id,
                "priority": i.priority,
                "status": i.status,
            }
            for i in rows
        ]
        ctx = ConversationContext(
            entity_type="issues_list",
            entity_id="batch",
            entity_data={"issues": issues_summary, "count": len(rows)},
            session_id=session_id,
        )
        question = ask.strip() if ask.strip() else None
        if question:
            result = svc.converse(session_id=session_id, message=question, context=ctx)
            if result.ai_used:
                console.print("\n[bold]AI:[/bold]")
                console.print(_parse_ai_response(result.value))
            else:
                console.print(f"[yellow]AI unavailable: {result.fallback_reason}[/yellow]")
        else:
            _ai_repl(svc, session_id, ctx, f"issues ({len(rows)} items)")


@issues.command("list")
@click.option(
    "--status", "-s", default=None, help="Filter by status (open, assigned, in_progress, etc.)"
)
@click.option(
    "--priority", "-p", default=None, help="Filter by priority (critical, high, medium, low)"
)
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--assigned-to", default=None, help="Filter by assignee")
@click.option("--limit", "-n", default=50, help="Max results")
def issues_list_cmd(
    status: str | None,
    priority: str | None,
    framework: str | None,
    assigned_to: str | None,
    limit: int,
) -> None:
    """List compliance issues (alias for 'warlock issues')."""
    # Delegate to the group's default behaviour
    ctx = click.get_current_context()
    ctx.invoke(
        issues,
        status=status,
        priority=priority,
        framework=framework,
        assigned_to=assigned_to,
        limit=limit,
        fmt=None,
        export_path=None,
        ask=None,
    )


@cli.command("issues-auto-create")
@click.option("--framework", "-f", default=None, help="Limit to a specific framework")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail (default: cli@warlock, env: WLK_CLI_ACTOR)",
)
def issues_auto_create(framework: str | None, actor: str | None) -> None:
    """Auto-create issues from non-compliant control results."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.issues import IssueManager

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    init_db()
    mgr = IssueManager()

    with get_session() as session:
        created = mgr.auto_create_from_results(session, framework=framework)

    if not created:
        console.print(
            "[dim]No new issues to create. All non-compliant results already have issues.[/dim]"
        )
        return

    console.print(f"[green]Created {len(created)} issue(s):[/green]")
    for issue in created:
        console.print(
            f"  [cyan]{issue.id[:8]}[/cyan] [{issue.priority}] {escape(issue.title[:70])}"
        )


@cli.command("poams")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--system", default=None, help="Filter by system profile ID or acronym")
@click.option("--status", "-s", default=None, help="Filter by status")
@click.option("--overdue", is_flag=True, help="Show only overdue POA&Ms")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default=None)
@click.option("--export", "export_path", default=None, help="Export to file (json/csv)")
@click.pass_context
def poams_list(
    ctx: click.Context,
    framework: str | None,
    system: str | None,
    status: str | None,
    overdue: bool,
    limit: int,
    fmt: str | None,
    export_path: str | None,
) -> None:
    """List Plans of Action & Milestones."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.poam import POAMManager

    init_db()
    mgr = POAMManager()

    with get_session() as session:
        if overdue:
            rows = mgr.get_overdue(session)
        else:
            rows = mgr.list_poams(session, framework=framework, status=status)

        # Filter by system profile if provided
        if system:
            sid = _resolve_system_id(session, system)
            rows = [r for r in rows if r.system_profile_id == sid]

    rows = rows[:limit]
    if not rows:
        console.print("[dim]No POA&Ms found.[/dim]")
        return

    from warlock.cli.output import format_output, get_output_format

    data = [
        {
            "id": p.id[:8],
            "framework": p.framework or "",
            "control_id": p.control_id or "",
            "severity": p.severity or "",
            "status": p.status or "",
            "due_date": (
                p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else ""
            ),
            "delays": str(p.delay_count or 0),
            "weakness": (p.weakness_description or "")[:40],
        }
        for p in rows
    ]

    _COLUMNS = [
        {"key": "id", "header": "ID", "max_width": "8"},
        {"key": "framework", "header": "Framework"},
        {"key": "control_id", "header": "Control"},
        {"key": "severity", "header": "Severity"},
        {"key": "status", "header": "Status"},
        {"key": "due_date", "header": "Due Date"},
        {"key": "delays", "header": "Delays", "justify": "right"},
        {"key": "weakness", "header": "Weakness", "max_width": "40"},
    ]

    format_output(
        data,
        _COLUMNS,
        fmt=get_output_format(ctx, fmt),
        title="Plans of Action & Milestones",
        style_map={
            "status": {
                "draft": "red",
                "open": "red",
                "in_progress": "yellow",
                "remediated": "green",
                "verified": "green",
                "completed": "green",
            },
        },
        export_path=export_path,
    )


@cli.command("compensating-controls")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", "-s", default=None, help="Filter by status")
def compensating_list(framework: str | None, status: str | None) -> None:
    """List compensating controls."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.compensating import CompensatingControlManager

    init_db()
    mgr = CompensatingControlManager()

    with get_session() as session:
        rows = mgr.list_controls(session, framework=framework, status=status)

    if not rows:
        console.print("[dim]No compensating controls found.[/dim]")
        return

    table = Table(title="Compensating Controls")
    table.add_column("ID", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Title", max_width=30)
    table.add_column("Status")
    table.add_column("Effectiveness", justify="right")
    table.add_column("Expiry")

    for c in rows:
        exp = c.expiry_date.strftime("%Y-%m-%d") if c.expiry_date else "\u2014"
        eff = f"{c.effectiveness_score:.0f}" if c.effectiveness_score else "\u2014"
        table.add_row(
            c.id[:8],
            c.original_framework,
            c.original_control_id,
            escape((c.title or "")[:30]),
            c.status,
            eff,
            exp,
        )

    console.print(table)


@cli.command("risk-acceptances")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", "-s", default=None, help="Filter by status")
@click.option(
    "--expiring-soon", type=int, default=None, help="Show acceptances expiring within N days"
)
def risk_acceptances_list(
    framework: str | None, status: str | None, expiring_soon: int | None
) -> None:
    """List risk acceptances."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.risk_acceptance import RiskAcceptanceManager

    init_db()
    mgr = RiskAcceptanceManager()

    with get_session() as session:
        rows = mgr.list_acceptances(
            session, framework=framework, status=status, expiring_days=expiring_soon
        )

    if not rows:
        console.print("[dim]No risk acceptances found.[/dim]")
        return

    table = Table(title="Risk Acceptances")
    table.add_column("ID", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Risk Level")
    table.add_column("Status")
    table.add_column("Approved By")
    table.add_column("Expires")

    for r in rows:
        exp = r.expiry_date.strftime("%Y-%m-%d") if r.expiry_date else "\u2014"
        table.add_row(
            r.id[:8],
            r.framework,
            r.control_id,
            r.risk_level,
            r.status,
            r.approved_by or "\u2014",
            exp,
        )

    console.print(table)


@cli.command("remediate")
@click.argument("item_id")
@click.option(
    "--action",
    "-a",
    type=click.Choice(["show", "assign", "transition", "accept-risk", "extend", "comment"]),
    default="show",
    help="Action to take",
)
@click.option(
    "--to",
    "to_value",
    required=False,
    help="Target value (email for assign, status for transition, days for extend)",
)
@click.option("--reason", required=False, help="Reason or comment text")
@click.option(
    "--ai/--no-ai", "use_ai", default=None, help="Override AI toggle for remediation guidance"
)
@click.option(
    "--ask", default=None, help="Ask AI a question about this item (interactive reasoning)"
)
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail (default: cli@warlock, env: WLK_CLI_ACTOR)",
)
def remediate(
    item_id: str,
    action: str,
    to_value: str | None,
    reason: str | None,
    use_ai: bool | None,
    ask: str | None,
    actor: str | None,
) -> None:
    """Show remediation guidance and take action on issues/POA&Ms.

    Default (no --action) shows the full remediation plan: what's wrong,
    how to fix it (CLI + manual steps), what evidence to collect, and
    the current workflow state.

    \b
    Examples:
        warlock remediate <id>                                    # show full remediation plan
        warlock remediate <id> -a assign --to eve@acme.com        # assign to someone
        warlock remediate <id> -a transition --to in_progress     # move to in_progress
        warlock remediate <id> -a accept-risk --reason "Low risk" # accept the risk
        warlock remediate <id> -a extend --to 30 --reason "Delay" # extend deadline by 30 days
        warlock remediate <id> -a comment --reason "Patch staged" # add a comment
        warlock remediate <id> --ask "What is the fastest way to fix this?"
        warlock remediate <id> --ai                              # AI-enhanced remediation plan

    Use 'warlock issues' or 'warlock poams' to find IDs.
    """

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import (
        Issue,
        POAM,
    )

    # If --actor was passed, override the env-based default
    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    init_db()
    with get_session() as session:
        # Try to find as issue first, then POA&M
        issue = session.query(Issue).filter(Issue.id.startswith(item_id)).first()
        poam = session.query(POAM).filter(POAM.id.startswith(item_id)).first()

        if not issue and not poam:
            _error(f"Not found: {item_id}. Use 'warlock issues' or 'warlock poams' to find IDs.")

        # --- SHOW MODE: full remediation plan ---
        if action == "show":
            if issue:
                _show_remediation_for_issue(session, issue)
            else:
                _show_remediation_for_poam(session, poam)
            return

        # --- ACTION MODE ---
        if issue:
            from warlock.workflows.issues import IssueManager

            mgr = IssueManager()

            actor = _get_actor()
            if action == "assign":
                if not to_value:
                    _error("--to <email> required")
                mgr.assign(session, issue.id, to_value, assigned_by=actor)
                console.print(f"[green]Issue {issue.id[:8]} assigned to {to_value}[/green]")
            elif action == "transition":
                if not to_value:
                    _error(
                        "--to <status> required. Valid: open, assigned, in_progress, resolved, closed, verified, risk_accepted"
                    )
                try:
                    mgr.transition(session, issue.id, to_value, actor=actor)
                    console.print(f"[green]Issue {issue.id[:8]} \u2192 {to_value}[/green]")
                except ValueError as e:
                    _error(str(e))
            elif action == "accept-risk":
                mgr.accept_risk(
                    session, issue.id, reason=reason or "Accepted via CLI", accepted_by=actor
                )
                console.print(f"[green]Issue {issue.id[:8]} risk accepted[/green]")
            elif action == "comment":
                if not reason:
                    _error("--reason <text> required")
                mgr.add_comment(session, issue.id, author=actor, content=reason)
                console.print(f"[green]Comment added to issue {issue.id[:8]}[/green]")
            elif action == "extend":
                _error(
                    "--action extend is not supported for issues. Use --action transition to change issue state."
                )

        elif poam:
            from warlock.workflows.poam import POAMManager

            mgr = POAMManager()
            actor = _get_actor()

            if action == "transition":
                if not to_value:
                    _error(
                        "--to <status> required. Valid: open, in_progress, remediated, verified, completed, risk_accepted, cancelled"
                    )
                try:
                    mgr.transition(session, poam.id, to_value, actor=actor)
                    console.print(f"[green]POA&M {poam.id[:8]} \u2192 {to_value}[/green]")
                except ValueError as e:
                    _error(str(e))
            elif action == "extend":
                if not to_value:
                    _error("--to <days> required")
                try:
                    days = int(to_value)
                except ValueError:
                    _error("--to must be number of days")
                from datetime import datetime, timedelta, timezone

                new_date = datetime.now(timezone.utc) + timedelta(days=days)
                mgr.extend(
                    session,
                    poam.id,
                    justification=reason or "Extended via CLI",
                    new_date=new_date,
                    approved_by=actor,
                )
                console.print(
                    f"[green]POA&M {poam.id[:8]} extended by {days} days (new deadline: {new_date.date()})[/green]"
                )
            elif action == "assign":
                _error("POA&Ms cannot be assigned directly. Assign the linked issue instead.")
            elif action == "accept-risk":
                try:
                    mgr.transition(session, poam.id, "risk_accepted", transitioned_by=actor)
                    console.print(f"[green]POA&M {poam.id[:8]} \u2192 risk_accepted[/green]")
                except ValueError as e:
                    _error(str(e))
            elif action == "comment":
                if not reason:
                    _error("--reason <text> required")
                # Add comment on linked issue if one exists, otherwise record as audit note
                from warlock.db.models import Issue

                linked_issue = session.query(Issue).filter(Issue.poam_id == poam.id).first()
                if linked_issue:
                    from warlock.workflows.issues import IssueManager

                    issue_mgr = IssueManager()
                    issue_mgr.add_comment(session, linked_issue.id, author=actor, content=reason)
                    console.print(
                        f"[green]Comment added to linked issue {linked_issue.id[:8]} for POA&M {poam.id[:8]}[/green]"
                    )
                else:
                    # Store as audit note in delay_justifications (the only list field available)
                    from datetime import datetime, timezone

                    notes = list(poam.delay_justifications or [])
                    notes.append(
                        {
                            "date": datetime.now(timezone.utc).isoformat(),
                            "justification": reason,
                            "approved_by": actor,
                            "type": "comment",
                        }
                    )
                    poam.delay_justifications = notes
                    session.commit()
                    console.print(f"[green]Audit note added to POA&M {poam.id[:8]}[/green]")

        # --ask: interactive AI reasoning about this item
        if ask is not None:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask, ConversationContext

            svc = get_ai_service()
            if not svc.is_available():
                console.print(
                    "[yellow]AI service not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.[/yellow]"
                )
                return

            entity_type = "issue" if issue else "poam"
            entity_id = issue.id if issue else poam.id
            entity_data: dict = {}
            if issue:
                entity_data = {
                    "title": issue.title,
                    "status": issue.status,
                    "priority": issue.priority,
                    "framework": issue.framework,
                    "control_id": issue.control_id,
                    "description": issue.description,
                }
            elif poam:
                entity_data = {
                    "weakness": poam.weakness_description,
                    "status": poam.status,
                    "severity": poam.severity,
                    "framework": poam.framework,
                    "control_id": poam.control_id,
                }

            import uuid

            session_id = uuid.uuid4().hex

            ctx = ConversationContext(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_data=entity_data,
                session_id=session_id,
            )

            question = ask.strip() if ask.strip() else None

            if question:
                result = svc.converse(session_id=session_id, message=question, context=ctx)
                if result.ai_used:
                    console.print("\n[bold]AI:[/bold]")
                    console.print(_parse_ai_response(result.value))
                else:
                    console.print(f"[yellow]AI unavailable: {result.fallback_reason}[/yellow]")
            else:
                _ai_repl(svc, session_id, ctx, f"{entity_type} {entity_id[:8]}")
            return

        # --ai: AI-enhanced remediation guidance appended to show mode
        if action == "show" and use_ai is not False:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import AITask

            svc = get_ai_service()
            if svc.is_task_enabled(AITask.REMEDIATION_GUIDANCE):
                ai_context: dict = {}
                if issue:
                    ai_context = {
                        "title": issue.title,
                        "framework": issue.framework,
                        "control_id": issue.control_id,
                        "priority": issue.priority,
                        "description": issue.description,
                    }
                elif poam:
                    ai_context = {
                        "weakness": poam.weakness_description,
                        "framework": poam.framework,
                        "control_id": poam.control_id,
                        "severity": poam.severity,
                    }
                try:
                    ai_result = svc.reason(AITask.REMEDIATION_GUIDANCE, context=ai_context)
                    if ai_result.ai_used:
                        console.print("\n[bold]AI Remediation Guidance:[/bold]")
                        value = ai_result.value
                        if isinstance(value, dict):
                            guidance_text = value.get("guidance") or value.get("narrative") or ""
                            steps = value.get("steps", [])
                            if guidance_text:
                                console.print(guidance_text)
                            if steps:
                                console.print("\n[bold]AI-suggested steps:[/bold]")
                                for i, step in enumerate(steps, 1):
                                    console.print(f"  {i}. {step}")
                        else:
                            console.print(str(value) if value else "")
                except Exception as exc:
                    console.print(f"\n[dim]AI guidance unavailable: {exc.__class__.__name__}[/dim]")


def _show_remediation_for_issue(session, issue) -> None:
    """Show full remediation guidance for an issue."""
    from rich.panel import Panel

    from warlock.db.models import CompensatingControl, ControlResult, POAM, RiskAcceptance

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]{escape(issue.title or '')}[/bold]\n\n"
            f"ID: {issue.id[:8]}  |  Framework: {issue.framework}  |  Control: {issue.control_id}\n"
            f"Status: [yellow]{issue.status}[/yellow]  |  Priority: {issue.priority}  |  "
            f"Assigned: {issue.assigned_to or '[dim]unassigned[/dim]'}",
            title="[bold red]Issue[/bold red]",
            border_style="red",
        )
    )

    # Description
    if issue.description:
        console.print(f"\n[bold]What's wrong:[/bold]\n{escape(issue.description)}")

    # Get the control result for remediation data
    result = None
    if issue.control_result_id:
        result = (
            session.query(ControlResult).filter(ControlResult.id == issue.control_result_id).first()
        )

    # Remediation steps from assertion engine
    if result and result.remediation_summary:
        console.print("\n[bold green]How to fix:[/bold green]")
        console.print(f"  {result.remediation_summary}")
        if result.remediation_steps:
            console.print("\n[bold]Manual steps:[/bold]")
            for i, step in enumerate(result.remediation_steps, 1):
                console.print(f"  {i}. {step}")
        if result.console_path:
            console.print(f"\n[bold]Console path:[/bold] {result.console_path}")

    if not (result and result.remediation_summary):
        from warlock.assessors.remediation_loader import get_remediation

        guidance = get_remediation(issue.framework, issue.control_id)
        if guidance:
            # Display from KB instead
            console.print("\n[bold green]How to fix:[/bold green]")
            console.print(f"  {guidance.get('summary', '')}")
            if guidance.get("remediation_steps"):
                console.print("\n[bold]Manual steps:[/bold]")
                for i, step in enumerate(guidance["remediation_steps"], 1):
                    console.print(f"  {i}. {step}")
            if guidance.get("console_path"):
                console.print(f"\n[bold]Console path:[/bold] {guidance['console_path']}")
            if guidance.get("recommended_reading"):
                console.print("\n[bold]Recommended reading:[/bold]")
                for ref in guidance["recommended_reading"]:
                    console.print(f"  - {ref}")

    # CLI remediation actions
    console.print("\n[bold cyan]CLI actions:[/bold cyan]")
    console.print(f"  warlock remediate {issue.id[:8]} -a assign --to <email>")
    console.print(f"  warlock remediate {issue.id[:8]} -a transition --to in_progress")
    console.print(f'  warlock remediate {issue.id[:8]} -a comment --reason "<update>"')
    console.print(f'  warlock remediate {issue.id[:8]} -a accept-risk --reason "<justification>"')

    # Evidence needed
    console.print("\n[bold]Evidence to collect:[/bold]")
    if result and result.assessor and result.assessor.startswith("assertion:"):
        assertion_name = result.assessor.split(":", 1)[1]
        console.print("  Re-run pipeline after fix: warlock collect")
        console.print(f"  Assertion '{assertion_name}' must pass on next assessment")
    else:
        console.print("  Re-run pipeline after fix: warlock collect")
        console.print(f"  Control {issue.control_id} must show as compliant")

    # Related items
    related_poam = (
        session.query(POAM)
        .filter(POAM.control_id == issue.control_id, POAM.framework == issue.framework)
        .first()
    )
    related_cc = (
        session.query(CompensatingControl)
        .filter(CompensatingControl.original_control_id == issue.control_id)
        .first()
    )
    related_ra = (
        session.query(RiskAcceptance).filter(RiskAcceptance.control_id == issue.control_id).first()
    )

    if related_poam or related_cc or related_ra:
        console.print("\n[bold]Related items:[/bold]")
        if related_poam:
            console.print(f"  POA&M: {related_poam.id[:8]} ({related_poam.status})")
        if related_cc:
            console.print(
                f"  Compensating control: {escape(related_cc.title or '')} ({related_cc.status})"
            )
        if related_ra:
            console.print(
                f"  Risk acceptance: {related_ra.id[:8]} ({related_ra.status}, expires {related_ra.expiry_date})"
            )

    console.print()


def _show_remediation_for_poam(session, poam) -> None:
    """Show full remediation guidance for a POA&M."""
    from rich.panel import Panel

    from warlock.db.models import CompensatingControl, ControlResult, RiskAcceptance

    console.print()
    console.print(
        Panel(
            f"[bold]{escape(poam.weakness_description or '')}[/bold]\n\n"
            f"ID: {poam.id[:8]}  |  Framework: {poam.framework}  |  Control: {poam.control_id}\n"
            f"Status: [yellow]{poam.status}[/yellow]  |  Severity: {poam.severity}  |  "
            f"Due: {poam.scheduled_completion or '[dim]no deadline[/dim]'}  |  Delays: {poam.delay_count}",
            title="[bold red]POA&M[/bold red]",
            border_style="red",
        )
    )

    # Get remediation from linked control result
    result = None
    if poam.control_result_id:
        result = (
            session.query(ControlResult).filter(ControlResult.id == poam.control_result_id).first()
        )
        if result and result.remediation_summary:
            console.print("\n[bold green]How to fix:[/bold green]")
            console.print(f"  {result.remediation_summary}")
            if result.remediation_steps:
                console.print("\n[bold]Manual steps:[/bold]")
                for i, step in enumerate(result.remediation_steps, 1):
                    console.print(f"  {i}. {step}")
            if result.console_path:
                console.print(f"\n[bold]Console path:[/bold] {result.console_path}")

    if not (result and result.remediation_summary):
        from warlock.assessors.remediation_loader import get_remediation

        guidance = get_remediation(poam.framework, poam.control_id)
        if guidance:
            # Display from KB instead
            console.print("\n[bold green]How to fix:[/bold green]")
            console.print(f"  {guidance.get('summary', '')}")
            if guidance.get("remediation_steps"):
                console.print("\n[bold]Manual steps:[/bold]")
                for i, step in enumerate(guidance["remediation_steps"], 1):
                    console.print(f"  {i}. {step}")
            if guidance.get("console_path"):
                console.print(f"\n[bold]Console path:[/bold] {guidance['console_path']}")
            if guidance.get("recommended_reading"):
                console.print("\n[bold]Recommended reading:[/bold]")
                for ref in guidance["recommended_reading"]:
                    console.print(f"  - {ref}")

    # Milestones
    if poam.milestones:
        console.print("\n[bold]Milestones:[/bold]")
        for m in poam.milestones:
            status = m.get("status", "pending")
            icon = "[green]done[/green]" if status == "completed" else "[yellow]pending[/yellow]"
            console.print(f"  {icon}  {m.get('description', '?')}")

    # CLI actions
    console.print("\n[bold cyan]CLI actions:[/bold cyan]")
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to open")
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to in_progress")
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to remediated")
    console.print(f'  warlock remediate {poam.id[:8]} -a extend --to 30 --reason "<justification>"')
    console.print(f"  warlock remediate {poam.id[:8]} -a transition --to risk_accepted")

    # Compensating controls
    cc = session.query(CompensatingControl).filter(CompensatingControl.poam_id == poam.id).first()
    if cc:
        console.print("\n[bold]Compensating control:[/bold]")
        console.print(
            f"  {escape(cc.title or '')} ({cc.status}, effectiveness: {cc.effectiveness_score}%)"
        )

    # Risk acceptance
    ra = session.query(RiskAcceptance).filter(RiskAcceptance.poam_id == poam.id).first()
    if ra:
        console.print("\n[bold]Risk acceptance:[/bold]")
        console.print(
            f"  {ra.status} \u2014 expires {ra.expiry_date} \u2014 approved by {ra.approved_by or 'pending'}"
        )

    console.print()


@cli.command("inheritance")
@click.option("--system", required=False, default=None, help="System profile ID or acronym")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def inheritance_list(system: str | None, framework: str | None) -> None:
    """Show control inheritance map for a system.

    When --system is omitted, lists available system profiles so you can
    pick one.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemProfile
    from warlock.workflows.inheritance import InheritanceManager

    init_db()

    if not system:
        # List available systems so the user knows what IDs to use
        with get_session() as session:
            profiles = (
                session.query(SystemProfile)
                .filter(SystemProfile.is_active == True)  # noqa: E712
                .order_by(SystemProfile.name)
                .all()
            )
        if not profiles:
            console.print("[dim]No system profiles found. Run the pipeline first.[/dim]")
            return
        console.print("[bold]Available systems:[/bold]")
        for sp in profiles:
            acr = f" ({escape(sp.acronym)})" if sp.acronym else ""
            console.print(f"  [cyan]{sp.id[:8]}[/cyan] {escape(sp.name or '')}{acr}")
        console.print("\n[dim]Use: warlock inheritance --system <id-or-acronym>[/dim]")
        return

    mgr = InheritanceManager()

    with get_session() as session:
        system_id = _resolve_system_id(session, system)
        rows = mgr.get_for_system(session, system_id, framework=framework)

    if not rows:
        console.print("[dim]No inheritance mappings found.[/dim]")
        return

    table = Table(title="Control Inheritance")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Type")
    table.add_column("Provider")
    table.add_column("Evidence Req")
    table.add_column("Status")

    for ci in rows:
        type_style = {
            "inherited": "cyan",
            "shared": "yellow",
            "common": "blue",
            "system_specific": "white",
        }.get(ci.inheritance_type, "white")
        table.add_row(
            ci.framework,
            ci.control_id,
            f"[{type_style}]{ci.inheritance_type}[/{type_style}]",
            ci.provider_system_id[:8] if ci.provider_system_id else "\u2014",
            ci.evidence_requirement,
            ci.status,
        )

    console.print(table)


@cli.command("dependencies")
@click.option("--system", default=None, help="Filter by system profile ID")
def dependencies_list(system: str | None) -> None:
    """Show cross-system dependency graph."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SystemDependency

    init_db()

    with get_session() as session:
        q = session.query(SystemDependency)
        if system:
            q = q.filter(
                (SystemDependency.consumer_system_id == system)
                | (SystemDependency.provider_system_id == system)
            )
        rows = q.all()

    if not rows:
        console.print("[dim]No system dependencies found.[/dim]")
        return

    table = Table(title="System Dependencies")
    table.add_column("Consumer", max_width=8)
    table.add_column("Provider", max_width=8)
    table.add_column("Type")
    table.add_column("Shared Controls")

    for d in rows:
        ctrls = ", ".join((d.shared_controls or [])[:3])
        if len(d.shared_controls or []) > 3:
            ctrls += f" (+{len(d.shared_controls) - 3})"
        table.add_row(
            d.consumer_system_id[:8],
            d.provider_system_id[:8],
            d.dependency_type,
            ctrls,
        )

    console.print(table)
