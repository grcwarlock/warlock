"""Branding configuration CLI commands."""

from __future__ import annotations

import click
from rich.markup import escape

from warlock.cli import cli, console


@cli.group("branding", invoke_without_command=True)
@click.pass_context
def branding(ctx: click.Context) -> None:
    """Per-tenant branding configuration for white-label deployments."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@branding.command("show")
@click.option("--tenant-id", default=None, help="Tenant ID (default: system tenant)")
def branding_show(tenant_id: str | None) -> None:
    """Show current branding configuration."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import DEFAULT_TENANT_ID, BrandingConfig

    init_db()
    tid = tenant_id or DEFAULT_TENANT_ID
    with get_read_session() as session:
        bc = session.query(BrandingConfig).filter(BrandingConfig.tenant_id == tid).first()

    if not bc:
        console.print("[dim]No branding configuration found for this tenant.[/dim]")
        return

    from rich.panel import Panel

    lines = [
        f"[bold]ID:[/bold]            {bc.id}",
        f"[bold]App Name:[/bold]      {escape(bc.app_name or 'Warlock')}",
        f"[bold]Primary Color:[/bold] {escape(bc.primary_color or '')}",
        f"[bold]Accent Color:[/bold]  {escape(bc.accent_color or '')}",
        f"[bold]Logo URL:[/bold]      {escape(bc.logo_url or '\u2014')}",
        f"[bold]Favicon URL:[/bold]   {escape(bc.favicon_url or '\u2014')}",
        "[bold]Custom CSS:[/bold]    "
        + (f"{len(bc.custom_css)} bytes" if bc.custom_css else "\u2014"),
    ]
    console.print(Panel("\n".join(lines), title="Branding Config", border_style="cyan"))


@branding.command("set")
@click.option("--tenant-id", default=None, help="Tenant ID (default: system tenant)")
@click.option("--app-name", default=None, help="Application name")
@click.option("--primary-color", default=None, help="Primary color hex (e.g. #6366f1)")
@click.option("--accent-color", default=None, help="Accent color hex")
@click.option("--logo-url", default=None, help="Logo image URL")
@click.option("--favicon-url", default=None, help="Favicon URL")
def branding_set(
    tenant_id: str | None,
    app_name: str | None,
    primary_color: str | None,
    accent_color: str | None,
    logo_url: str | None,
    favicon_url: str | None,
) -> None:
    """Update branding configuration."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DEFAULT_TENANT_ID, BrandingConfig, _uuid

    init_db()
    tid = tenant_id or DEFAULT_TENANT_ID

    with get_session() as session:
        bc = session.query(BrandingConfig).filter(BrandingConfig.tenant_id == tid).first()
        if not bc:
            bc = BrandingConfig(id=_uuid(), tenant_id=tid, tenant_id_unique=tid)
            session.add(bc)

        if app_name is not None:
            bc.app_name = app_name
        if primary_color is not None:
            bc.primary_color = primary_color
        if accent_color is not None:
            bc.accent_color = accent_color
        if logo_url is not None:
            bc.logo_url = logo_url
        if favicon_url is not None:
            bc.favicon_url = favicon_url

    console.print("[green]Branding configuration updated.[/green]")
