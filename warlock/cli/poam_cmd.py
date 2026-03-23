"""POA&M detail commands: milestones, milestone-update, deviation.

NOTE: governance.py has a flat ``warlock poams`` (plural) command that lists
POA&Ms. This module registers a ``warlock poam`` (singular) *group* with
sub-commands for working with individual POA&M records. Different name, no
collision.
"""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("poam")
def poam_group() -> None:
    """POA&M detail management: milestones, updates, and deviations."""


# ---------------------------------------------------------------------------
# milestones
# ---------------------------------------------------------------------------


@poam_group.command("milestones")
@click.argument("poam_id")
def poam_milestones(poam_id: str) -> None:
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
        console.print("[dim]No milestones defined for this POA&M.[/dim]")
        console.print(
            f"[dim]Use 'warlock poam milestone-update {poam_id} <milestone_id>' "
            f"to add or update milestones.[/dim]"
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
