"""Evidence request (PBC list) CLI commands.

Manages the lifecycle of evidence requests during audit engagements.
"""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import _error, _get_actor, cli, console


@cli.group("evidence-requests", invoke_without_command=True)
@click.pass_context
def evidence_requests(ctx: click.Context) -> None:
    """Evidence request (PBC list) management."""
    if ctx.invoked_subcommand is not None:
        return

    # Default: show summary of all evidence requests
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import EvidenceRequest

    init_db()
    with get_read_session() as session:
        all_reqs = session.query(EvidenceRequest).all()

    if not all_reqs:
        console.print("[dim]No evidence requests found.[/dim]")
        return

    counts: dict[str, int] = {}
    for r in all_reqs:
        counts[r.status] = counts.get(r.status, 0) + 1

    table = Table(title=f"Evidence Requests ({len(all_reqs)})")
    table.add_column("Status")
    table.add_column("Count", justify="right")

    status_styles = {
        "requested": "yellow",
        "uploaded": "cyan",
        "accepted": "green",
        "rejected": "red",
    }
    for st in ("requested", "uploaded", "accepted", "rejected"):
        count = counts.get(st, 0)
        if count > 0:
            style = status_styles.get(st, "")
            table.add_row(f"[{style}]{st}[/]", str(count))

    console.print(table)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@evidence_requests.command("create")
@click.option("--engagement", "-e", required=True, help="Engagement ID")
@click.option("--control", "-c", required=True, help="Control ID")
@click.option("--assignee", "-a", required=True, help="Assignee email")
@click.option("--due", "-d", required=True, help="Due date (YYYY-MM-DD)")
@click.option("--description", default=None, help="Evidence description")
@click.option("--framework", "-f", default=None, help="Framework override")
def create_request(
    engagement: str,
    control: str,
    assignee: str,
    due: str,
    description: str | None,
    framework: str | None,
) -> None:
    """Create an evidence request for an audit engagement."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.evidence_requests import EvidenceRequestManager

    init_db()
    actor = _get_actor()

    try:
        due_date = datetime.strptime(due, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(f"Invalid date format: {due}. Use YYYY-MM-DD.")
        return  # unreachable, _error raises SystemExit

    desc = description or f"Evidence needed for control {control}"

    try:
        with get_session() as session:
            mgr = EvidenceRequestManager()
            req = mgr.create_request(
                session=session,
                engagement_id=engagement,
                control_id=control,
                description=desc,
                assignee=assignee,
                due_date=due_date,
                framework=framework,
                actor=actor,
            )
            console.print(
                f"[green]Evidence request created:[/green] "
                f"[cyan]{req.id[:8]}[/cyan] -- {escape(control)} -> {escape(assignee)}"
            )
    except ValueError as e:
        _error(str(e))


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@evidence_requests.command("list")
@click.option("--engagement", "-e", required=True, help="Engagement ID")
@click.option(
    "--status",
    "-s",
    default=None,
    type=click.Choice(["requested", "uploaded", "accepted", "rejected"]),
    help="Filter by status",
)
def list_requests(engagement: str, status: str | None) -> None:
    """List evidence requests for an engagement."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.workflows.evidence_requests import EvidenceRequestManager

    init_db()
    with get_read_session() as session:
        mgr = EvidenceRequestManager()
        reqs = mgr.list_requests(session, engagement, status=status)

    if not reqs:
        console.print("[dim]No evidence requests found.[/dim]")
        return

    table = Table(title=f"Evidence Requests ({len(reqs)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Control", max_width=15)
    table.add_column("Framework", style="dim")
    table.add_column("Status")
    table.add_column("Description", max_width=40)
    table.add_column("Created", style="dim")

    status_styles = {
        "requested": "yellow",
        "uploaded": "cyan",
        "accepted": "green",
        "rejected": "red",
    }

    for r in reqs:
        st_style = status_styles.get(r.status, "")
        created = r.created_at.strftime("%Y-%m-%d") if r.created_at else "\u2014"
        table.add_row(
            r.id[:8],
            escape(r.control_id or "\u2014"),
            escape(r.framework or "\u2014"),
            f"[{st_style}]{r.status}[/]",
            escape((r.description or "\u2014")[:40]),
            created,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# fulfill
# ---------------------------------------------------------------------------


@evidence_requests.command("fulfill")
@click.argument("request_id")
@click.option("--evidence", "-e", required=True, help="Evidence file path or reference")
@click.option("--notes", "-n", default=None, help="Fulfillment notes")
def fulfill_request(request_id: str, evidence: str, notes: str | None) -> None:
    """Upload evidence to fulfill a request."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.evidence_requests import EvidenceRequestManager

    init_db()
    actor = _get_actor()

    try:
        with get_session() as session:
            mgr = EvidenceRequestManager()
            req = mgr.fulfill(
                session=session,
                request_id=request_id,
                evidence_path=evidence,
                fulfilled_by=actor,
                notes=notes,
            )
            console.print(
                f"[green]Evidence request {req.id[:8]} fulfilled[/green] -- "
                f"evidence: {escape(evidence)}"
            )
    except ValueError as e:
        _error(str(e))


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------


@evidence_requests.command("review")
@click.argument("request_id")
@click.option(
    "--decision",
    "-d",
    required=True,
    type=click.Choice(["accept", "reject"]),
    help="Accept or reject the evidence",
)
@click.option("--notes", "-n", default=None, help="Review notes")
def review_request(request_id: str, decision: str, notes: str | None) -> None:
    """Review uploaded evidence (accept or reject)."""
    from warlock.db.engine import get_session, init_db
    from warlock.workflows.evidence_requests import EvidenceRequestManager

    init_db()
    actor = _get_actor()

    try:
        with get_session() as session:
            mgr = EvidenceRequestManager()
            req = mgr.review(
                session=session,
                request_id=request_id,
                decision=decision,
                reviewer=actor,
                notes=notes,
            )
            style = "green" if decision == "accept" else "red"
            console.print(f"[{style}]Evidence request {req.id[:8]} {decision}ed[/{style}]")
    except ValueError as e:
        _error(str(e))


# ---------------------------------------------------------------------------
# overdue
# ---------------------------------------------------------------------------


@evidence_requests.command("overdue")
@click.option("--engagement", "-e", default=None, help="Filter by engagement ID")
def overdue_requests(engagement: str | None) -> None:
    """List all overdue evidence requests."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.workflows.evidence_requests import EvidenceRequestManager

    init_db()
    with get_read_session() as session:
        mgr = EvidenceRequestManager()
        overdue = mgr.find_overdue(session, engagement)

    if not overdue:
        console.print("[green]No overdue evidence requests.[/green]")
        return

    table = Table(title=f"Overdue Evidence Requests ({len(overdue)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Control")
    table.add_column("Framework", style="dim")
    table.add_column("Assignee")
    table.add_column("Days Overdue", justify="right", style="red")
    table.add_column("Status")

    for r in overdue:
        table.add_row(
            r["id"][:8],
            escape(r["control_id"] or "\u2014"),
            escape(r["framework"] or "\u2014"),
            escape(r["assignee"]),
            str(r["days_overdue"]),
            escape(r["status"]),
        )

    console.print(table)
