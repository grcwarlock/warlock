"""CLI commands for attestation management.

Attestations are sign-off records that track who asserted compliance for a
given control or framework, when, and in what state.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error, _get_actor


@cli.group("attestations")
def attestations() -> None:
    """Manage control attestations and sign-offs."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATUS_STYLES: dict[str, str] = {
    "draft": "dim",
    "submitted": "yellow",
    "reviewed": "cyan",
    "approved": "green bold",
    "rejected": "red",
}


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return "\u2014"
    return dt.strftime("%Y-%m-%d")


def _fmt_actor(value: str | None) -> str:
    return value or "\u2014"


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@attestations.command("list")
@click.option(
    "--status",
    "-s",
    type=click.Choice(["draft", "submitted", "reviewed", "approved", "rejected"]),
    default=None,
    help="Filter by status",
)
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def attestations_list(
    status: str | None,
    framework: str | None,
    output_format: str,
) -> None:
    """List attestations, optionally filtered by status or framework."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation

    init_db()

    with get_session() as session:
        q = session.query(Attestation)
        if status:
            q = q.filter(Attestation.status == status)
        if framework:
            q = q.filter(Attestation.framework == framework)
        q = q.order_by(Attestation.created_at.desc())
        rows = q.all()

    if not rows:
        console.print("[dim]No attestations found.[/dim]")
        return

    if output_format == "json":
        data = [
            {
                "id": a.id,
                "framework": a.framework,
                "control_id": a.control_id,
                "status": a.status,
                "prepared_by": a.prepared_by,
                "approved_by": a.approved_by,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in rows
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Attestations ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Status")
    table.add_column("Prepared By", max_width=30)
    table.add_column("Approved By", max_width=30)
    table.add_column("Created")

    for a in rows:
        style = _STATUS_STYLES.get(a.status, "")
        table.add_row(
            a.id[:8],
            a.framework,
            a.control_id or "(framework-level)",
            f"[{style}]{a.status}[/{style}]" if style else a.status,
            _fmt_actor(a.prepared_by),
            _fmt_actor(a.approved_by),
            _fmt_date(a.created_at),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@attestations.command("create")
@click.option("--control", "control_id", required=True, help="Control ID to attest (e.g. AC-2)")
@click.option("--statement", required=True, help="Attestation statement text")
@click.option("--owner", required=True, help="Owner user ID / email")
@click.option(
    "--due-date",
    default=None,
    help="Due date in YYYY-MM-DD format (stored as prepared_at if provided)",
)
@click.option("--framework", "-f", default="nist_800_53", help="Framework (default: nist_800_53)")
def attestation_create(
    control_id: str,
    statement: str,
    owner: str,
    due_date: str | None,
    framework: str,
) -> None:
    """Create a new attestation in draft status."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation

    init_db()

    prepared_at: datetime | None = None
    if due_date:
        try:
            prepared_at = datetime.strptime(due_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            _error(f"Invalid date format '{due_date}'. Use YYYY-MM-DD.")

    with get_session() as session:
        attest = Attestation(
            framework=framework,
            control_id=control_id,
            status="draft",
            statement=statement,
            prepared_by=owner,
            prepared_at=prepared_at or datetime.now(timezone.utc),
        )
        session.add(attest)
        session.commit()
        attest_id = attest.id

    console.print(
        f"[green]Attestation created:[/green] [cyan]{attest_id[:8]}[/cyan] "
        f"({framework} / {control_id}, status=draft)"
    )


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@attestations.command("show")
@click.argument("attest_id")
def attestation_show(attest_id: str) -> None:
    """Show full details of an attestation."""
    from rich.panel import Panel

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation

    init_db()

    with get_session() as session:
        attest = session.query(Attestation).filter(Attestation.id.startswith(attest_id)).first()

    if not attest:
        _error(f"Attestation not found: {attest_id}")

    style = _STATUS_STYLES.get(attest.status, "")
    status_str = f"[{style}]{attest.status}[/{style}]" if style else attest.status

    lines = [
        f"ID: {attest.id}",
        f"Framework: {attest.framework}   Control: {attest.control_id or '(framework-level)'}",
        f"Status: {status_str}",
        "",
        f"[bold]Statement:[/bold] {attest.statement}",
        "",
        f"Prepared by: {_fmt_actor(attest.prepared_by)}  at {_fmt_date(attest.prepared_at)}",
        f"Submitted by: {_fmt_actor(attest.submitted_by)}  at {_fmt_date(attest.submitted_at)}",
        f"Reviewed by: {_fmt_actor(attest.reviewed_by)}  at {_fmt_date(attest.reviewed_at)}",
        f"Approved by: {_fmt_actor(attest.approved_by)}  at {_fmt_date(attest.approved_at)}",
    ]

    if attest.rejection_reason:
        lines.append(f"[red]Rejection reason:[/red] {attest.rejection_reason}")
    if attest.review_notes:
        lines.append(f"Review notes: {attest.review_notes}")

    console.print(Panel("\n".join(lines), title="[bold]Attestation[/bold]", border_style="cyan"))


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------


@attestations.command("sign")
@click.argument("attest_id")
@click.option(
    "--as",
    "actor",
    default=None,
    help="Actor signing the attestation (default: WLK_CLI_ACTOR env)",
)
def attestation_sign(attest_id: str, actor: str | None) -> None:
    """Sign (approve) an attestation.

    Moves the attestation from 'reviewed' or 'submitted' to 'approved'.
    If the attestation is still in 'draft', it is first submitted, then approved.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation

    init_db()
    signer = actor or _get_actor()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        attest = session.query(Attestation).filter(Attestation.id.startswith(attest_id)).first()

        if not attest:
            _error(f"Attestation not found: {attest_id}")

        if attest.status == "approved":
            console.print(f"[yellow]Attestation {attest.id[:8]} is already approved.[/yellow]")
            return

        if attest.status in ("draft", "submitted"):
            attest.submitted_by = attest.submitted_by or signer
            attest.submitted_at = attest.submitted_at or now
            attest.reviewed_by = signer
            attest.reviewed_at = now
            attest.status = "reviewed"

        attest.approved_by = signer
        attest.approved_at = now
        attest.status = "approved"
        attest.updated_at = now
        session.commit()
        short_id = attest.id[:8]

    console.print(f"[green]Attestation {short_id} approved by {signer} at {now.date()}[/green]")


# ---------------------------------------------------------------------------
# overdue
# ---------------------------------------------------------------------------


@attestations.command("overdue")
def attestation_overdue() -> None:
    """Show attestations that are past their prepared_at due date and not yet approved."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation

    init_db()
    now = datetime.now(timezone.utc)

    with get_session() as session:
        rows = (
            session.query(Attestation)
            .filter(
                Attestation.status.notin_(["approved", "rejected"]),
                Attestation.prepared_at < now,
            )
            .order_by(Attestation.prepared_at.asc())
            .all()
        )

    if not rows:
        console.print("[green]No overdue attestations.[/green]")
        return

    table = Table(title=f"Overdue Attestations ({len(rows)})", style="red")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Status")
    table.add_column("Due Date")
    table.add_column("Days Overdue", justify="right")
    table.add_column("Prepared By")

    for a in rows:
        if a.prepared_at:
            delta = (now - a.prepared_at).days
        else:
            delta = 0
        style = _STATUS_STYLES.get(a.status, "")
        table.add_row(
            a.id[:8],
            a.framework,
            a.control_id or "(framework-level)",
            f"[{style}]{a.status}[/{style}]" if style else a.status,
            _fmt_date(a.prepared_at),
            f"[red]{delta}[/red]",
            _fmt_actor(a.prepared_by),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# expiring
# ---------------------------------------------------------------------------


@attestations.command("expiring")
@click.option("--days", "-d", default=30, type=int, help="Show attestations expiring within N days")
def attestation_expiring(days: int) -> None:
    """Show approved attestations expiring within N days (based on approved_at + 365 days)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation
    from datetime import timedelta

    init_db()
    now = datetime.now(timezone.utc)
    window_end = now + timedelta(days=days)
    one_year = timedelta(days=365)

    with get_session() as session:
        rows = (
            session.query(Attestation)
            .filter(Attestation.status == "approved", Attestation.approved_at.isnot(None))
            .order_by(Attestation.approved_at.asc())
            .all()
        )

    expiring = [
        a for a in rows if a.approved_at and now <= (a.approved_at + one_year) <= window_end
    ]

    if not expiring:
        console.print(f"[green]No attestations expiring within {days} days.[/green]")
        return

    table = Table(title=f"Attestations Expiring Within {days} Days ({len(expiring)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Framework", style="cyan")
    table.add_column("Control")
    table.add_column("Approved By")
    table.add_column("Approved At")
    table.add_column("Expires")
    table.add_column("Days Left", justify="right")

    for a in expiring:
        expiry = a.approved_at + one_year
        days_left = (expiry - now).days
        colour = "yellow" if days_left <= 7 else "cyan"
        table.add_row(
            a.id[:8],
            a.framework,
            a.control_id or "(framework-level)",
            _fmt_actor(a.approved_by),
            _fmt_date(a.approved_at),
            expiry.strftime("%Y-%m-%d"),
            f"[{colour}]{days_left}[/{colour}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@attestations.command("report")
@click.option("--framework", "-f", default=None, help="Limit report to a single framework")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["md", "json"]),
    default="md",
    help="Output format",
)
def attestation_report(framework: str | None, output_format: str) -> None:
    """Generate an attestation summary report by framework."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation

    init_db()

    with get_session() as session:
        q = session.query(Attestation)
        if framework:
            q = q.filter(Attestation.framework == framework)
        rows = q.all()

    if not rows:
        console.print("[dim]No attestations found.[/dim]")
        return

    # Aggregate by framework + status
    from collections import defaultdict

    by_framework: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for a in rows:
        by_framework[a.framework][a.status] += 1

    all_statuses = ["draft", "submitted", "reviewed", "approved", "rejected"]

    if output_format == "json":
        report_data = {fw: dict(counts) for fw, counts in sorted(by_framework.items())}
        console.print(json.dumps(report_data, indent=2))
        return

    # Markdown output
    lines = ["# Attestation Report", "", f"Generated: {datetime.now(timezone.utc).date()}", ""]
    for fw, counts in sorted(by_framework.items()):
        total = sum(counts.values())
        approved = counts.get("approved", 0)
        lines.append(f"## {fw}")
        lines.append(f"- Total: {total}")
        lines.append(f"- Approved: {approved}")
        for st in all_statuses:
            if counts.get(st, 0):
                lines.append(f"- {st.capitalize()}: {counts[st]}")
        lines.append("")

    console.print("\n".join(lines))


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@attestations.command("history")
@click.argument("attest_id")
def attestation_history(attest_id: str) -> None:
    """Show the audit trail for an attestation."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Attestation, AuditEntry

    init_db()

    with get_session() as session:
        attest = session.query(Attestation).filter(Attestation.id.startswith(attest_id)).first()
        if not attest:
            _error(f"Attestation not found: {attest_id}")

        audit_rows = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "attestation",
                AuditEntry.entity_id == attest.id,
            )
            .order_by(AuditEntry.sequence.asc())
            .all()
        )

    console.print(
        f"\n[bold]Audit trail for attestation {attest.id[:8]}[/bold] "
        f"({attest.framework} / {attest.control_id or 'framework-level'})"
    )

    # Show key workflow milestones from the model itself
    milestones = [
        ("created", attest.created_at, attest.prepared_by),
        ("submitted", attest.submitted_at, attest.submitted_by),
        ("reviewed", attest.reviewed_at, attest.reviewed_by),
        ("approved", attest.approved_at, attest.approved_by),
        ("rejected", attest.rejected_at, attest.rejected_by),
    ]

    table = Table(title="Workflow Timeline")
    table.add_column("Event", style="cyan")
    table.add_column("Date")
    table.add_column("Actor", style="dim")

    for event, dt, actor in milestones:
        if dt is not None:
            table.add_row(event, _fmt_date(dt), _fmt_actor(actor))

    console.print(table)

    if audit_rows:
        console.print("\n[bold]Audit log entries:[/bold]")
        for entry in audit_rows:
            console.print(
                f"  [{entry.created_at.strftime('%Y-%m-%d %H:%M')}] "
                f"[cyan]{entry.action}[/cyan]  by {entry.actor}"
            )
    else:
        console.print("[dim](No audit log entries recorded for this attestation)[/dim]")
