"""Tenant management CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("tenants", invoke_without_command=True)
@click.pass_context
def tenants(ctx: click.Context) -> None:
    """Multi-tenant management."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@tenants.command("list")
@click.option("--active/--all", default=True, help="Show only active tenants (default: active)")
@click.option("--limit", "-n", default=50, help="Max results")
def tenants_list(active: bool, limit: int) -> None:
    """List tenants."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import Tenant

    init_db()
    with get_read_session() as session:
        q = session.query(Tenant)
        if active:
            q = q.filter(Tenant.is_active.is_(True))
        rows = q.order_by(Tenant.name).limit(limit).all()

    if not rows:
        console.print("[dim]No tenants found.[/dim]")
        return

    table = Table(title=f"Tenants ({len(rows)})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Slug")
    table.add_column("Active")
    table.add_column("Created", style="dim")

    from warlock.utils import ensure_aware

    for t in rows:
        table.add_row(
            t.id[:8],
            escape(t.name or ""),
            escape(t.slug or ""),
            "[green]Yes[/green]" if t.is_active else "[dim]No[/dim]",
            ensure_aware(t.created_at).strftime("%Y-%m-%d") if t.created_at else "\u2014",
        )

    console.print(table)


@tenants.command("show")
@click.argument("tenant_id")
def tenants_show(tenant_id: str) -> None:
    """Show detail for a tenant."""
    import json

    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import Tenant

    init_db()
    with get_read_session() as session:
        tenant = session.query(Tenant).filter(Tenant.id.startswith(tenant_id)).first()

    if not tenant:
        console.print(f"[red]Tenant not found: {escape(tenant_id)}[/red]")
        return

    from rich.panel import Panel

    from warlock.utils import ensure_aware

    overrides = json.dumps(tenant.config_overrides or {}, indent=2)
    lines = [
        f"[bold]ID:[/bold]        {tenant.id}",
        f"[bold]Name:[/bold]      {escape(tenant.name or '')}",
        f"[bold]Slug:[/bold]      {escape(tenant.slug or '')}",
        f"[bold]Active:[/bold]    {'Yes' if tenant.is_active else 'No'}",
        "[bold]Created:[/bold]   "
        + (
            ensure_aware(tenant.created_at).strftime("%Y-%m-%d %H:%M")
            if tenant.created_at
            else "\u2014"
        ),
        f"[bold]Overrides:[/bold]\n{escape(overrides)}",
    ]
    console.print(Panel("\n".join(lines), title="Tenant Detail", border_style="cyan"))
