"""Dead letter queue CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("dlq", invoke_without_command=True)
@click.pass_context
def dlq(ctx: click.Context) -> None:
    """Dead letter queue: inspect and retry failed pipeline events."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@dlq.command("list")
@click.option("--status", default=None, help="Filter by status (failed, retried, purged)")
@click.option("--event-type", default=None, help="Filter by event type")
@click.option("--limit", "-n", default=50, help="Max results")
def dlq_list(status: str | None, event_type: str | None, limit: int) -> None:
    """List dead letter queue entries."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import DeadLetterEntry

    init_db()
    with get_read_session() as session:
        q = session.query(DeadLetterEntry)
        if status:
            q = q.filter(DeadLetterEntry.status == status)
        if event_type:
            q = q.filter(DeadLetterEntry.event_type == event_type)
        rows = q.order_by(DeadLetterEntry.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No dead letter entries found.[/dim]")
        return

    table = Table(title=f"Dead Letter Queue ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Event Type", style="cyan")
    table.add_column("Error", max_width=40)
    table.add_column("Retries", justify="right")
    table.add_column("Status")
    table.add_column("Created", style="dim")

    from warlock.utils import ensure_aware

    for e in rows:
        status_style = {"failed": "red", "retried": "yellow", "purged": "dim"}.get(e.status, "")
        table.add_row(
            e.id[:8],
            escape(e.event_type or ""),
            escape((e.error_message or "")[:40]),
            str(e.retry_count),
            f"[{status_style}]{escape(e.status or '')}[/{status_style}]"
            if status_style
            else escape(e.status or ""),
            ensure_aware(e.created_at).strftime("%Y-%m-%d %H:%M") if e.created_at else "\u2014",
        )

    console.print(table)


@dlq.command("retry")
@click.argument("entry_id")
def dlq_retry(entry_id: str) -> None:
    """Mark a DLQ entry for retry."""
    from datetime import datetime, timezone

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DeadLetterEntry

    init_db()
    with get_session() as session:
        entry = (
            session.query(DeadLetterEntry).filter(DeadLetterEntry.id.startswith(entry_id)).first()
        )
        if not entry:
            console.print(f"[red]DLQ entry not found: {escape(entry_id)}[/red]")
            return
        entry.status = "retried"
        entry.retry_count = (entry.retry_count or 0) + 1
        entry.last_retry_at = datetime.now(timezone.utc)

    console.print(f"[green]Marked entry {entry_id[:8]} for retry.[/green]")


@dlq.command("purge")
@click.option("--all", "purge_all", is_flag=True, help="Purge all failed entries")
@click.confirmation_option(prompt="Are you sure you want to purge DLQ entries?")
def dlq_purge(purge_all: bool) -> None:
    """Purge failed DLQ entries."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DeadLetterEntry

    init_db()
    with get_session() as session:
        q = session.query(DeadLetterEntry)
        if not purge_all:
            q = q.filter(DeadLetterEntry.status == "failed")
        count = q.count()
        q.update({"status": "purged"})

    console.print(f"[green]Purged {count} DLQ entries.[/green]")
