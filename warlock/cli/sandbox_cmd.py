"""Sandbox environment CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("sandbox", invoke_without_command=True)
@click.pass_context
def sandbox(ctx: click.Context) -> None:
    """Sandbox environment management for policy testing."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@sandbox.command("list")
@click.option("--status", default=None, help="Filter by status (active, expired, archived)")
@click.option("--limit", "-n", default=50, help="Max results")
def sandbox_list(status: str | None, limit: int) -> None:
    """List sandbox environments."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import SandboxEnvironment

    init_db()
    with get_read_session() as session:
        q = session.query(SandboxEnvironment)
        if status:
            q = q.filter(SandboxEnvironment.status == status)
        rows = q.order_by(SandboxEnvironment.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No sandbox environments found.[/dim]")
        return

    table = Table(title=f"Sandbox Environments ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Owner", style="dim")
    table.add_column("Status")
    table.add_column("Created", style="dim")

    from warlock.utils import ensure_aware

    for s in rows:
        status_style = {"active": "green", "expired": "yellow", "archived": "dim"}.get(s.status, "")
        table.add_row(
            s.id[:8],
            escape(s.name or ""),
            s.owner_id[:8] if s.owner_id else "\u2014",
            f"[{status_style}]{escape(s.status or '')}[/{status_style}]"
            if status_style
            else escape(s.status or ""),
            ensure_aware(s.created_at).strftime("%Y-%m-%d %H:%M") if s.created_at else "\u2014",
        )

    console.print(table)


@sandbox.command("show")
@click.argument("sandbox_id")
def sandbox_show(sandbox_id: str) -> None:
    """Show detail for a sandbox environment."""
    import json

    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import SandboxEnvironment

    init_db()
    with get_read_session() as session:
        sb = (
            session.query(SandboxEnvironment)
            .filter(SandboxEnvironment.id.startswith(sandbox_id))
            .first()
        )

    if not sb:
        console.print(f"[red]Sandbox not found: {escape(sandbox_id)}[/red]")
        return

    from rich.panel import Panel

    from warlock.utils import ensure_aware

    config_str = json.dumps(sb.config or {}, indent=2)
    lines = [
        f"[bold]ID:[/bold]       {sb.id}",
        f"[bold]Name:[/bold]     {escape(sb.name or '')}",
        f"[bold]Owner:[/bold]    {sb.owner_id or '\u2014'}",
        f"[bold]Status:[/bold]   {escape(sb.status or '')}",
        f"[bold]Created:[/bold]  {ensure_aware(sb.created_at):%Y-%m-%d %H:%M}",
        "[bold]Expires:[/bold]  "
        + (f"{ensure_aware(sb.expires_at):%Y-%m-%d %H:%M}" if sb.expires_at else "\u2014"),
        f"[bold]Config:[/bold]\n{escape(config_str)}",
    ]
    console.print(Panel("\n".join(lines), title="Sandbox Detail", border_style="cyan"))
