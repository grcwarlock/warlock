"""IP allowlist CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("ip-allowlist", invoke_without_command=True)
@click.pass_context
def ip_allowlist(ctx: click.Context) -> None:
    """IP allowlist management for API access restriction."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@ip_allowlist.command("list")
@click.option("--active/--all", default=True, help="Show only active entries (default: active)")
@click.option("--limit", "-n", default=50, help="Max results")
def allowlist_list(active: bool, limit: int) -> None:
    """List IP allowlist entries."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import IPAllowlistEntry

    init_db()
    with get_read_session() as session:
        q = session.query(IPAllowlistEntry)
        if active:
            q = q.filter(IPAllowlistEntry.active.is_(True))
        rows = q.order_by(IPAllowlistEntry.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No IP allowlist entries found.[/dim]")
        return

    table = Table(title=f"IP Allowlist ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("CIDR", style="cyan")
    table.add_column("Description", max_width=40)
    table.add_column("Active")
    table.add_column("Created By", style="dim")
    table.add_column("Expires", style="dim")

    from warlock.utils import ensure_aware

    for e in rows:
        expires = ensure_aware(e.expires_at).strftime("%Y-%m-%d") if e.expires_at else "\u2014"
        table.add_row(
            e.id[:8],
            escape(e.cidr or ""),
            escape((e.description or "")[:40]),
            "[green]Yes[/green]" if e.active else "[dim]No[/dim]",
            escape(e.created_by or "\u2014"),
            expires,
        )

    console.print(table)


@ip_allowlist.command("add")
@click.option("--cidr", required=True, help="CIDR block (e.g. 10.0.0.0/8, 203.0.113.5/32)")
@click.option("--description", "-d", default=None, help="Description of this entry")
@click.option("--expires-days", default=None, type=int, help="Expiry in days from now")
def allowlist_add(cidr: str, description: str | None, expires_days: int | None) -> None:
    """Add an IP allowlist entry."""
    from datetime import datetime, timedelta, timezone

    from warlock.cli import _get_actor
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import IPAllowlistEntry, _uuid

    init_db()
    expires_at = None
    if expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

    with get_session() as session:
        entry = IPAllowlistEntry(
            id=_uuid(),
            cidr=cidr,
            description=description,
            active=True,
            created_by=_get_actor(),
            expires_at=expires_at,
        )
        session.add(entry)

    console.print(f"[green]IP allowlist entry added: {escape(cidr)} ({entry.id[:8]})[/green]")


@ip_allowlist.command("remove")
@click.argument("entry_id")
def allowlist_remove(entry_id: str) -> None:
    """Deactivate an IP allowlist entry."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import IPAllowlistEntry

    init_db()
    with get_session() as session:
        entry = (
            session.query(IPAllowlistEntry).filter(IPAllowlistEntry.id.startswith(entry_id)).first()
        )
        if not entry:
            console.print(f"[red]Entry not found: {escape(entry_id)}[/red]")
            return
        entry.active = False

    console.print(f"[green]IP allowlist entry {entry_id[:8]} deactivated.[/green]")
