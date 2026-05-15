"""POA&M commands: create, list, show, close, milestones, milestone-update, deviation.

NOTE: governance.py has a flat ``warlock poams`` (plural) command that lists
POA&Ms. This module registers a ``warlock poam`` (singular) *group* with
sub-commands for working with individual POA&M records. Different name, no
collision.
"""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console
from warlock.utils import ensure_aware

# ---------------------------------------------------------------------------
# Style maps
# ---------------------------------------------------------------------------

_SEV_STYLES: dict[str, str] = {
    "critical": "red bold",
    "high": "red",
    "moderate": "yellow",
    "low": "dim",
}

_ST_STYLES: dict[str, str] = {
    "draft": "dim",
    "open": "yellow",
    "in_progress": "cyan",
    "completed": "green",
    "verified": "green bold",
    "closed": "dim",
}

_VALID_STATUSES = ["draft", "open", "in_progress", "completed", "verified", "closed"]


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("poam", invoke_without_command=True)
@click.pass_context
def poam_group(ctx: click.Context) -> None:
    """POA&M lifecycle management: create, list, show, close, milestones, deviations."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@poam_group.command("create")
@click.option("--control", "-c", required=True, help="Control ID")
@click.option("--framework", "-f", required=True, help="Framework")
@click.option("--weakness", "-w", required=True, help="Weakness description")
@click.option("--remediation", "-r", required=True, help="Remediation plan")
@click.option("--due-date", required=True, help="Scheduled completion YYYY-MM-DD")
@click.option("--assigned-to", default=None, help="Assignee")
@click.option(
    "--severity",
    "-s",
    default="moderate",
    type=click.Choice(["critical", "high", "moderate", "low"]),
    help="Severity level",
)
@click.option("--finding-id", "finding_id", default=None, help="Related finding ID")
@click.option(
    "--cost", "cost_estimate", default=None, type=float, help="Estimated remediation cost in USD"
)
@click.option("--resource-allocation", default=None, help="Resource allocation description")
def poam_create(
    control: str,
    framework: str,
    weakness: str,
    remediation: str,
    due_date: str,
    assigned_to: str | None,
    severity: str,
    finding_id: str | None,
    cost_estimate: float | None,
    resource_allocation: str | None,
) -> None:
    """Create a new POA&M entry."""
    import uuid

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    try:
        scheduled = datetime.strptime(due_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(f"Invalid --due-date format: {due_date}. Use YYYY-MM-DD.")

    with get_session() as session:
        poam = POAM(
            id=str(uuid.uuid4()),
            framework=framework,
            control_id=control,
            weakness_description=weakness,
            severity=severity,
            status="open",
            resources_required=remediation,
            scheduled_completion=scheduled,
            created_by=actor,
            updated_by=assigned_to or actor,
            milestones=[],
            delay_justifications=[],
            created_at=now,
            updated_at=now,
            finding_id=finding_id,
            cost_estimate=cost_estimate,
            resource_allocation=resource_allocation,
        )
        session.add(poam)

        # SEC-C4: canonical hash-chained trail.
        from warlock.db.audit import AuditTrail

        AuditTrail(session).record(
            action="poam_created",
            entity_type="poam",
            entity_id=poam.id,
            actor=actor,
            metadata={
                "framework": framework,
                "control_id": control,
                "severity": severity,
                "weakness": weakness[:200],
            },
        )
        session.commit()

        console.print(
            f"[green]POA&M created:[/green] [cyan]{poam.id[:8]}[/cyan] "
            f"{escape(framework)}/{escape(control)} — due {due_date}"
        )


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@poam_group.command("list")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--status",
    "-s",
    default=None,
    type=click.Choice(_VALID_STATUSES + [""]),
    help="Filter by status",
)
@click.option("--overdue", is_flag=True, help="Show only overdue POA&Ms")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json", "csv"]),
    help="Output format",
)
def poam_list(
    framework: str | None,
    status: str | None,
    overdue: bool,
    limit: int,
    fmt: str,
) -> None:
    """List POA&M entries with optional filters."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.poam import POAMManager

    init_db()
    mgr = POAMManager()

    with get_session() as session:
        if overdue:
            rows = mgr.get_overdue(session)
        else:
            rows = mgr.list_poams(session, framework=framework, status=status)
        rows = rows[:limit]

    if not rows:
        console.print("[dim]No POA&Ms found.[/dim]")
        return

    if fmt in ("json", "csv"):
        out = [
            {
                "id": p.id,
                "framework": p.framework,
                "control_id": p.control_id,
                "weakness": (p.weakness_description or "")[:80],
                "severity": p.severity,
                "status": p.status,
                "scheduled_completion": (
                    p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else None
                ),
                "created_by": p.created_by,
            }
            for p in rows
        ]
        if fmt == "csv":
            from warlock.cli.output import render_csv

            render_csv(out, keys=list(out[0].keys()) if out else [])
        else:
            console.print_json(data=out)
        return

    table = Table(title=f"POA&Ms ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Weakness", max_width=40)
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Due", style="dim")

    now = datetime.now(timezone.utc)
    for p in rows:
        sev_style = _SEV_STYLES.get(p.severity, "")
        st_style = _ST_STYLES.get(p.status, "")
        due_str = (
            p.scheduled_completion.strftime("%Y-%m-%d") if p.scheduled_completion else "\u2014"
        )
        overdue_flag = ""
        if (
            p.scheduled_completion
            and ensure_aware(p.scheduled_completion) < now
            and p.status not in ("completed", "verified", "closed")
        ):
            overdue_flag = " [red]OVERDUE[/red]"
        table.add_row(
            p.id[:8],
            escape(p.framework or ""),
            escape(p.control_id or ""),
            escape((p.weakness_description or "")[:40]),
            f"[{sev_style}]{p.severity}[/{sev_style}]" if sev_style else escape(p.severity or ""),
            f"[{st_style}]{p.status}[/{st_style}]" if st_style else escape(p.status or ""),
            f"{due_str}{overdue_flag}",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@poam_group.command("show")
@click.argument("poam_id")
def poam_show(poam_id: str) -> None:
    """Show full detail for a POA&M entry."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM

    init_db()
    with get_session() as session:
        poam = session.query(POAM).filter(POAM.id.startswith(poam_id)).first()
        if not poam:
            _error(f"POA&M not found: {poam_id}")

        sev_style = _SEV_STYLES.get(poam.severity, "")
        st_style = _ST_STYLES.get(poam.status, "")
        due_str = (
            poam.scheduled_completion.strftime("%Y-%m-%d")
            if poam.scheduled_completion
            else "\u2014"
        )
        actual_str = (
            poam.actual_completion.strftime("%Y-%m-%d") if poam.actual_completion else "\u2014"
        )

        console.print()
        console.print(
            Panel(
                f"[bold]{escape(poam.framework)}/{escape(poam.control_id)}[/bold]\n\n"
                f"ID: {poam.id}\n"
                f"Severity: "
                f"{'[' + sev_style + ']' + poam.severity + '[/' + sev_style + ']' if sev_style else poam.severity}"
                f"  |  Status: "
                f"{'[' + st_style + ']' + poam.status + '[/' + st_style + ']' if st_style else poam.status}"
                f"  |  "
                f"Risk Level: {poam.risk_level or 'n/a'}\n"
                f"Scheduled: {due_str}  |  Actual: {actual_str}\n"
                f"Created by: {escape(poam.created_by or 'n/a')}  |  "
                f"Approved by: {escape(poam.approved_by or 'n/a')}",
                title="[bold cyan]POA&M[/bold cyan]",
                border_style="cyan",
            )
        )

        console.print(f"\n[bold]Weakness:[/bold]\n{escape(poam.weakness_description or 'n/a')}")

        if poam.resources_required:
            console.print(f"\n[bold]Remediation Plan:[/bold]\n{escape(poam.resources_required)}")

        if poam.vendor_dependency:
            console.print(f"\n[bold]Vendor Dependency:[/bold] {escape(poam.vendor_dependency)}")

        milestones = list(poam.milestones or [])
        if milestones:
            console.print(f"\n[bold]Milestones ({len(milestones)}):[/bold]")
            for i, ms in enumerate(milestones, 1):
                ms_status = ms.get("status", "pending")
                console.print(
                    f"  {i}. {escape(ms.get('description', 'n/a'))} "
                    f"— {ms_status} (due: {ms.get('due_date', 'n/a')})"
                )

        deviations = list(poam.delay_justifications or [])
        if deviations:
            console.print(f"\n[bold]Deviations/Justifications ({len(deviations)}):[/bold]")
            for d in deviations:
                console.print(
                    f"  - [{d.get('deviation_type', d.get('type', 'n/a'))}] "
                    f"{escape(d.get('reason', d.get('justification', 'n/a')))}"
                )

        console.print(
            f"\n[dim]Delay count: {poam.delay_count or 0}  |  "
            f"Finding: {poam.finding_id or 'n/a'}  |  "
            f"Control result: {poam.control_result_id or 'n/a'}[/dim]"
        )
        console.print()


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


@poam_group.command("close")
@click.argument("poam_id")
@click.option("--note", "-n", default="Completed", help="Completion note")
def poam_close(poam_id: str, note: str) -> None:
    """Mark a POA&M as completed and closed."""

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM

    init_db()
    actor = _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        poam = session.query(POAM).filter(POAM.id.startswith(poam_id)).first()
        if not poam:
            _error(f"POA&M not found: {poam_id}")

        old_status = poam.status
        poam.status = "completed"
        poam.actual_completion = now
        poam.updated_by = actor
        poam.updated_at = now

        # SEC-C4: canonical hash-chained trail.
        from warlock.db.audit import AuditTrail

        AuditTrail(session).record(
            action="poam_closed",
            entity_type="poam",
            entity_id=poam.id,
            actor=actor,
            metadata={
                "old_status": old_status,
                "new_status": "completed",
                "note": note,
                "framework": poam.framework,
                "control_id": poam.control_id,
            },
        )
        session.commit()

    console.print(f"[green]POA&M {poam_id[:8]} closed:[/green] {old_status} \u2192 completed")
    console.print(f"  Note: {escape(note)}")


# ---------------------------------------------------------------------------
# milestones
# ---------------------------------------------------------------------------


@poam_group.command("milestones")
@click.argument("poam_id")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json", "csv"]),
    help="Output format",
)
def poam_milestones(poam_id: str, fmt: str) -> None:
    """Show all milestones for a POA&M.

    POAM_ID: POA&M ID or prefix (from 'warlock poams').
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM

    init_db()
    with get_session() as session:
        poam = session.query(POAM).filter(POAM.id.startswith(poam_id)).first()
        if not poam:
            _error(f"POA&M not found: {poam_id}. Use 'warlock poams' to list IDs.")

        milestones = list(poam.milestones or [])
        poam_display = {
            "id": poam.id[:8],
            "framework": poam.framework,
            "control_id": poam.control_id,
            "status": poam.status,
            "severity": poam.severity,
            "weakness": (poam.weakness_description or "")[:80],
            "scheduled_completion": (
                poam.scheduled_completion.strftime("%Y-%m-%d")
                if poam.scheduled_completion
                else "\u2014"
            ),
        }

    console.print(
        f"\n[bold]POA&M {poam_display['id']}[/bold] — "
        f"{poam_display['framework']}/{poam_display['control_id']} "
        f"[{poam_display['status']}]"
    )
    console.print(f"Weakness: {poam_display['weakness']}")
    console.print(f"Scheduled completion: {poam_display['scheduled_completion']}\n")

    if not milestones:
        if fmt in ("json", "csv"):
            import json as _json

            if fmt == "csv":
                from warlock.cli.output import render_csv

                render_csv([], keys=[])
            else:
                console.print(_json.dumps({"poam": poam_display, "milestones": []}, indent=2))
            return
        console.print("[dim]No milestones defined for this POA&M.[/dim]")
        console.print(
            f"[dim]Use 'warlock poam milestone-update {poam_id} <milestone_id>' "
            f"to add or update milestones.[/dim]"
        )
        return

    if fmt in ("json", "csv"):
        import json as _json

        if fmt == "csv":
            from warlock.cli.output import render_csv

            render_csv(milestones, keys=list(milestones[0].keys()) if milestones else [])
        else:
            console.print(
                _json.dumps({"poam": poam_display, "milestones": milestones}, indent=2, default=str)
            )
        return

    table = Table(title=f"Milestones ({len(milestones)})")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Description", max_width=50)
    table.add_column("Due Date")
    table.add_column("Status")
    table.add_column("Completed")

    for i, ms in enumerate(milestones, 1):
        status = ms.get("status", "pending")
        status_style = (
            "green" if status == "completed" else ("yellow" if status == "in_progress" else "dim")
        )
        due = ms.get("due_date", "\u2014")
        completed = ms.get("completed_date", "\u2014")
        table.add_row(
            str(i),
            ms.get("description", "")[:50],
            str(due),
            f"[{status_style}]{status}[/{status_style}]",
            str(completed),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# milestone-update
# ---------------------------------------------------------------------------


@poam_group.command("milestone-update")
@click.argument("poam_id")
@click.argument("milestone_id", type=int)
@click.option(
    "--status",
    "-s",
    type=click.Choice(["pending", "in_progress", "completed", "delayed"]),
    required=True,
    help="New milestone status",
)
@click.option("--description", "-d", default=None, help="Update milestone description")
@click.option("--due-date", default=None, help="Set or update due date (YYYY-MM-DD)")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail",
)
def poam_milestone_update(
    poam_id: str,
    milestone_id: int,
    status: str,
    description: str | None,
    due_date: str | None,
    actor: str | None,
) -> None:
    """Update a specific milestone on a POA&M.

    POAM_ID: POA&M ID or prefix.\n
    MILESTONE_ID: 1-based milestone index (from 'warlock poam milestones <id>').
    """
    import os

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    actor_name = _get_actor()

    init_db()
    with get_session() as session:
        poam = session.query(POAM).filter(POAM.id.startswith(poam_id)).first()
        if not poam:
            _error(f"POA&M not found: {poam_id}")

        milestones = list(poam.milestones or [])

        # milestone_id is 1-based
        idx = milestone_id - 1
        if idx < 0 or idx >= len(milestones):
            if not milestones and milestone_id == 1:
                # Create first milestone
                milestones = [{}]
            else:
                _error(
                    f"Milestone {milestone_id} not found. "
                    f"This POA&M has {len(milestones)} milestone(s)."
                )

        ms = dict(milestones[idx])
        ms["status"] = status
        if description:
            ms["description"] = description
        if due_date:
            ms["due_date"] = due_date
        if status == "completed":
            ms["completed_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        ms["updated_by"] = actor_name
        ms["updated_at"] = datetime.now(timezone.utc).isoformat()

        milestones[idx] = ms
        poam.milestones = milestones
        poam.updated_by = actor_name
        session.commit()

    console.print(
        f"[green]Milestone {milestone_id} on POA&M {poam_id[:8]} updated to '{status}'.[/green]"
    )
    if status == "completed":
        console.print(
            f"[dim]Completed date recorded: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}[/dim]"
        )


# ---------------------------------------------------------------------------
# deviation
# ---------------------------------------------------------------------------


@poam_group.command("deviation")
@click.argument("poam_id")
@click.option(
    "--type",
    "deviation_type",
    required=True,
    type=click.Choice(
        [
            "false-positive",
            "vendor-dependency",
            "operational-requirement",
            "risk-accepted",
            "compensating-control",
        ]
    ),
    help="Deviation type",
)
@click.option("--reason", "-r", required=True, help="Justification for the deviation")
@click.option("--expiry", default=None, help="Expiry date for the deviation (YYYY-MM-DD)")
@click.option(
    "--actor",
    default=None,
    envvar="WLK_CLI_ACTOR",
    help="Actor identity for audit trail",
)
def poam_deviation(
    poam_id: str,
    deviation_type: str,
    reason: str,
    expiry: str | None,
    actor: str | None,
) -> None:
    """Record a deviation on a POA&M (false positive, vendor dependency, etc.).

    POAM_ID: POA&M ID or prefix.

    Deviations are recorded in the POA&M's delay_justifications history
    and included in the monthly ConMon report.
    """
    import os

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM

    if actor:
        os.environ["WLK_CLI_ACTOR"] = actor

    actor_name = _get_actor()
    now = datetime.now(timezone.utc)

    init_db()
    with get_session() as session:
        poam = session.query(POAM).filter(POAM.id.startswith(poam_id)).first()
        if not poam:
            _error(f"POA&M not found: {poam_id}. Use 'warlock poams' to list IDs.")

        justifications = list(poam.delay_justifications or [])
        deviation_record: dict = {
            "type": "deviation",
            "deviation_type": deviation_type,
            "reason": reason,
            "recorded_by": actor_name,
            "recorded_at": now.isoformat(),
        }
        if expiry:
            deviation_record["expiry"] = expiry

        justifications.append(deviation_record)
        poam.delay_justifications = justifications
        poam.updated_by = actor_name
        session.commit()

    console.print(f"[green]Deviation recorded on POA&M {poam_id[:8]}:[/green]")
    console.print(f"  Type:    {deviation_type}")
    console.print(f"  Reason:  {reason}")
    console.print(f"  By:      {actor_name}")
    if expiry:
        console.print(f"  Expiry:  {expiry}")
    console.print(f"\n[dim]Total deviation records: {len(poam.delay_justifications or [])}[/dim]")


# ---------------------------------------------------------------------------
# cost — POAM-1
# ---------------------------------------------------------------------------


@poam_group.command("cost")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json", "csv"]),
    help="Output format",
)
def poam_cost(framework: str | None, fmt: str) -> None:
    """Show cost summary for POA&Ms aggregated by framework and status."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.poam import POAMManager

    init_db()
    mgr = POAMManager()
    with get_session() as session:
        rows = mgr.cost_summary(session, framework=framework)

    if not rows:
        console.print("[dim]No POA&Ms with cost data found.[/dim]")
        return

    if fmt in ("json", "csv"):
        if fmt == "csv":
            from warlock.cli.output import render_csv

            render_csv(rows, keys=list(rows[0].keys()) if rows else [])
        else:
            console.print_json(data=rows)
        return

    table = Table(title="POA&M Cost Summary")
    table.add_column("Framework")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    table.add_column("Total Cost (USD)", justify="right")

    grand_total = 0.0
    grand_count = 0
    for row in sorted(rows, key=lambda r: (r["framework"], r["status"])):
        st_style = _ST_STYLES.get(row["status"], "")
        st_text = f"[{st_style}]{row['status']}[/{st_style}]" if st_style else escape(row["status"])
        table.add_row(
            escape(row["framework"]),
            st_text,
            str(row["count"]),
            f"${row['total_cost']:,.2f}",
        )
        grand_total += row["total_cost"]
        grand_count += row["count"]

    table.add_section()
    table.add_row("[bold]TOTAL[/bold]", "", str(grand_count), f"[bold]${grand_total:,.2f}[/bold]")
    console.print(table)


# ---------------------------------------------------------------------------
# overdue — POAM-3
# ---------------------------------------------------------------------------


@poam_group.command("overdue")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format",
    "fmt",
    default="table",
    type=click.Choice(["table", "json", "csv"]),
    help="Output format",
)
def poam_overdue(framework: str | None, fmt: str) -> None:
    """Show overdue POA&Ms with days overdue and severity."""
    from warlock.db.engine import get_session, init_db
    from warlock.utils import ensure_aware
    from warlock.workflows.poam import POAMManager

    init_db()
    mgr = POAMManager()
    with get_session() as session:
        overdue_poams = mgr.check_overdue(session)

        if framework:
            overdue_poams = [p for p in overdue_poams if p.framework == framework]

        now = datetime.now(timezone.utc)
        rows_data = []
        for p in overdue_poams:
            sched = ensure_aware(p.scheduled_completion)
            days_overdue = (now - sched).days
            rows_data.append(
                {
                    "id": p.id,
                    "framework": p.framework,
                    "control_id": p.control_id,
                    "severity": p.severity,
                    "status": p.status,
                    "scheduled_completion": sched.strftime("%Y-%m-%d"),
                    "days_overdue": days_overdue,
                    "cost_estimate": p.cost_estimate,
                }
            )

    if not rows_data:
        console.print("[green]No overdue POA&Ms found.[/green]")
        return

    if fmt in ("json", "csv"):
        if fmt == "csv":
            from warlock.cli.output import render_csv

            render_csv(rows_data, keys=list(rows_data[0].keys()) if rows_data else [])
        else:
            console.print_json(data=rows_data)
        return

    table = Table(title=f"Overdue POA&Ms ({len(rows_data)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Due Date")
    table.add_column("Days Overdue", justify="right")
    table.add_column("Cost (USD)", justify="right")

    for row in sorted(rows_data, key=lambda r: r["days_overdue"], reverse=True):
        sev_style = _SEV_STYLES.get(row["severity"], "")
        st_style = _ST_STYLES.get(row["status"], "")
        days_style = "red bold" if row["days_overdue"] > 30 else "yellow"
        cost_str = f"${row['cost_estimate']:,.2f}" if row["cost_estimate"] else "\u2014"
        sev_text = (
            f"[{sev_style}]{escape(row['severity'])}[/{sev_style}]"
            if sev_style
            else escape(row["severity"])
        )
        st_text = (
            f"[{st_style}]{escape(row['status'])}[/{st_style}]"
            if st_style
            else escape(row["status"])
        )
        table.add_row(
            row["id"][:8],
            escape(row["framework"]),
            escape(row["control_id"]),
            sev_text,
            st_text,
            row["scheduled_completion"],
            f"[{days_style}]{row['days_overdue']}[/{days_style}]",
            cost_str,
        )

    console.print(table)

    # Summary by severity (count from already-loaded data)
    sev_counts: dict[str, int] = {}
    for row in rows_data:
        sev_counts[row["severity"]] = sev_counts.get(row["severity"], 0) + 1
    if sev_counts:
        console.print("\n[bold]By severity:[/bold]", end="  ")
        parts = []
        for sev, cnt in sorted(sev_counts.items()):
            sev_style = _SEV_STYLES.get(sev, "")
            if sev_style:
                parts.append(f"[{sev_style}]{escape(sev)}[/{sev_style}]: {cnt}")
            else:
                parts.append(f"{escape(sev)}: {cnt}")
        console.print("  ".join(parts))


# ---------------------------------------------------------------------------
# bulk-update — POAM-4
# ---------------------------------------------------------------------------


@poam_group.command("bulk-update")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--severity",
    "-s",
    default=None,
    type=click.Choice(["critical", "high", "moderate", "low"]),
    help="Filter by severity",
)
@click.option(
    "--status",
    required=True,
    type=click.Choice(
        ["open", "in_progress", "remediated", "verified", "completed", "risk_accepted", "cancelled"]
    ),
    help="Target status",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def poam_bulk_update(
    framework: str | None,
    severity: str | None,
    status: str,
    yes: bool,
) -> None:
    """Batch update status for multiple POA&Ms by framework/severity."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM
    from warlock.workflows.poam import _CLOSED_STATUSES, POAMManager

    init_db()
    actor = _get_actor()

    with get_session() as session:
        # Preview how many will be affected
        query = session.query(POAM).filter(~POAM.status.in_(_CLOSED_STATUSES))
        if framework:
            query = query.filter(POAM.framework == framework)
        if severity:
            query = query.filter(POAM.severity == severity)
        count = query.count()

        if count == 0:
            console.print("[dim]No matching POA&Ms found.[/dim]")
            return

        if not yes:
            filters = []
            if framework:
                filters.append(f"framework={framework}")
            if severity:
                filters.append(f"severity={severity}")
            filter_str = ", ".join(filters) if filters else "all open"
            if not click.confirm(f"Update {count} POA&Ms ({filter_str}) to status '{status}'?"):
                console.print("[dim]Cancelled.[/dim]")
                return

        mgr = POAMManager()
        updated = mgr.bulk_update_status(
            session,
            new_status=status,
            actor=actor,
            framework=framework,
            severity=severity,
        )
        session.commit()

    console.print(f"[green]Updated {len(updated)}/{count} POA&Ms to '{status}'.[/green]")
    if len(updated) < count:
        console.print(
            f"[yellow]{count - len(updated)} POA&Ms skipped (invalid transition).[/yellow]"
        )


# ---------------------------------------------------------------------------
# bulk-assign — POAM-4
# ---------------------------------------------------------------------------


@poam_group.command("bulk-assign")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--severity",
    "-s",
    default=None,
    type=click.Choice(["critical", "high", "moderate", "low"]),
    help="Filter by severity",
)
@click.option("--assignee", "-a", required=True, help="User to assign POA&Ms to")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def poam_bulk_assign(
    framework: str | None,
    severity: str | None,
    assignee: str,
    yes: bool,
) -> None:
    """Batch assign POA&Ms to a user by framework/severity."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import POAM
    from warlock.workflows.poam import _CLOSED_STATUSES, POAMManager

    init_db()
    actor = _get_actor()

    with get_session() as session:
        query = session.query(POAM).filter(~POAM.status.in_(_CLOSED_STATUSES))
        if framework:
            query = query.filter(POAM.framework == framework)
        if severity:
            query = query.filter(POAM.severity == severity)
        count = query.count()

        if count == 0:
            console.print("[dim]No matching POA&Ms found.[/dim]")
            return

        if not yes:
            filters = []
            if framework:
                filters.append(f"framework={framework}")
            if severity:
                filters.append(f"severity={severity}")
            filter_str = ", ".join(filters) if filters else "all open"
            if not click.confirm(f"Assign {count} POA&Ms ({filter_str}) to '{assignee}'?"):
                console.print("[dim]Cancelled.[/dim]")
                return

        mgr = POAMManager()
        assigned = mgr.bulk_assign(
            session,
            assigned_to=assignee,
            actor=actor,
            framework=framework,
            severity=severity,
        )
        session.commit()

    console.print(f"[green]Assigned {len(assigned)} POA&Ms to '{escape(assignee)}'.[/green]")
