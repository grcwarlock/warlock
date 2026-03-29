"""Compliance obligation CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("obligations", invoke_without_command=True)
@click.pass_context
def obligations(ctx: click.Context) -> None:
    """Recurring compliance obligations (audits, filings, assessments)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@obligations.command("list")
@click.option("--status", default=None, help="Filter by status (pending, completed, overdue)")
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--limit", "-n", default=50, help="Max results")
def obligations_list(status: str | None, framework: str | None, limit: int) -> None:
    """List compliance obligations."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ComplianceObligation

    init_db()
    with get_read_session() as session:
        q = session.query(ComplianceObligation)
        if status:
            q = q.filter(ComplianceObligation.status == status)
        if framework:
            q = q.filter(ComplianceObligation.framework == framework)
        rows = q.order_by(ComplianceObligation.next_due).limit(limit).all()

    if not rows:
        console.print("[dim]No compliance obligations found.[/dim]")
        return

    table = Table(title=f"Compliance Obligations ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Title", style="cyan", max_width=40)
    table.add_column("Framework")
    table.add_column("Type")
    table.add_column("Frequency")
    table.add_column("Next Due", style="dim")
    table.add_column("Status")

    from warlock.utils import ensure_aware

    for o in rows:
        status_style = {
            "pending": "yellow",
            "in_progress": "cyan",
            "completed": "green",
            "overdue": "red bold",
        }.get(o.status, "")
        due = ensure_aware(o.next_due).strftime("%Y-%m-%d") if o.next_due else "\u2014"
        table.add_row(
            o.id[:8],
            escape((o.title or "")[:40]),
            escape(o.framework or "\u2014"),
            escape(o.obligation_type or "\u2014"),
            escape(o.frequency or "\u2014"),
            due,
            f"[{status_style}]{escape(o.status or '')}[/{status_style}]"
            if status_style
            else escape(o.status or ""),
        )

    console.print(table)


@obligations.command("show")
@click.argument("obligation_id")
def obligations_show(obligation_id: str) -> None:
    """Show detail for a compliance obligation."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ComplianceObligation

    init_db()
    with get_read_session() as session:
        ob = (
            session.query(ComplianceObligation)
            .filter(ComplianceObligation.id.startswith(obligation_id))
            .first()
        )

    if not ob:
        console.print(f"[red]Obligation not found: {escape(obligation_id)}[/red]")
        return

    from rich.panel import Panel

    from warlock.utils import ensure_aware

    lines = [
        f"[bold]ID:[/bold]         {ob.id}",
        f"[bold]Title:[/bold]      {escape(ob.title or '')}",
        f"[bold]Framework:[/bold]  {escape(ob.framework or '\u2014')}",
        f"[bold]Control:[/bold]    {escape(ob.control_id or '\u2014')}",
        f"[bold]Type:[/bold]       {escape(ob.obligation_type or '\u2014')}",
        f"[bold]Frequency:[/bold]  {escape(ob.frequency or '\u2014')}",
        f"[bold]Owner:[/bold]      {escape(ob.owner or '\u2014')}",
        f"[bold]Status:[/bold]     {escape(ob.status or '')}",
        "[bold]Next Due:[/bold]   "
        + (ensure_aware(ob.next_due).strftime("%Y-%m-%d") if ob.next_due else "\u2014"),
        "[bold]Completed:[/bold]  "
        + (
            ensure_aware(ob.completed_at).strftime("%Y-%m-%d %H:%M")
            if ob.completed_at
            else "\u2014"
        ),
        f"[bold]Notes:[/bold]      {escape(ob.notes or '\u2014')}",
    ]
    console.print(Panel("\n".join(lines), title="Obligation Detail", border_style="cyan"))
