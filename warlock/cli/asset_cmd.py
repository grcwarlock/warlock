"""Asset inventory CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("assets", invoke_without_command=True)
@click.pass_context
def assets(ctx: click.Context) -> None:
    """Asset inventory management."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@assets.command("list")
@click.option("--type", "resource_type", default=None, help="Filter by resource type")
@click.option("--system", "-s", default=None, help="Filter by system profile ID or acronym")
@click.option("--status", default=None, help="Filter by status (active, decommissioned)")
@click.option("--limit", "-n", default=50, help="Max results")
def assets_list(
    resource_type: str | None,
    system: str | None,
    status: str | None,
    limit: int,
) -> None:
    """List discovered assets."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import Asset

    init_db()
    with get_read_session() as session:
        q = session.query(Asset)
        if resource_type:
            q = q.filter(Asset.resource_type == resource_type)
        if status:
            q = q.filter(Asset.status == status)
        if system:
            from warlock.cli import _resolve_system_id

            sid = _resolve_system_id(session, system)
            q = q.filter(Asset.system_id == sid)
        rows = q.order_by(Asset.last_seen.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No assets found.[/dim]")
        return

    table = Table(title=f"Assets ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Resource ID", style="cyan", max_width=30)
    table.add_column("Type")
    table.add_column("Name", max_width=30)
    table.add_column("Owner", style="dim")
    table.add_column("Classification")
    table.add_column("Status")

    for a in rows:
        table.add_row(
            a.id[:8],
            escape(a.resource_id[:30] if a.resource_id else ""),
            escape(a.resource_type or ""),
            escape((a.resource_name or "")[:30]),
            escape(a.owner or "\u2014"),
            escape(a.classification or "\u2014"),
            escape(a.status or "active"),
        )

    console.print(table)


@assets.command("show")
@click.argument("asset_id")
def assets_show(asset_id: str) -> None:
    """Show full detail for an asset."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import Asset

    init_db()
    with get_read_session() as session:
        asset = session.query(Asset).filter(Asset.id.startswith(asset_id)).first()

    if not asset:
        console.print(f"[red]Asset not found: {escape(asset_id)}[/red]")
        return

    from rich.panel import Panel

    from warlock.utils import ensure_aware

    lines = [
        f"[bold]ID:[/bold]             {asset.id}",
        f"[bold]Resource ID:[/bold]    {escape(asset.resource_id or '')}",
        f"[bold]Type:[/bold]           {escape(asset.resource_type or '')}",
        f"[bold]Name:[/bold]           {escape(asset.resource_name or '')}",
        f"[bold]Owner:[/bold]          {escape(asset.owner or '\u2014')}",
        f"[bold]Classification:[/bold] {escape(asset.classification or '\u2014')}",
        f"[bold]Criticality:[/bold]    {asset.criticality or '\u2014'}",
        f"[bold]Status:[/bold]         {escape(asset.status or 'active')}",
        f"[bold]System ID:[/bold]      {asset.system_id or '\u2014'}",
        f"[bold]First seen:[/bold]     {ensure_aware(asset.first_seen):%Y-%m-%d %H:%M}",
        f"[bold]Last seen:[/bold]      {ensure_aware(asset.last_seen):%Y-%m-%d %H:%M}",
    ]
    console.print(Panel("\n".join(lines), title="Asset Detail", border_style="cyan"))
