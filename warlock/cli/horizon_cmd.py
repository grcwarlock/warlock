"""Regulatory horizon scanning CLI commands.

Provides feed listing and refresh for regulatory change monitoring.
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("horizon", invoke_without_command=True)
@click.pass_context
def horizon(ctx: click.Context) -> None:
    """Regulatory horizon scanning and change monitoring."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        console.print("\n[dim]Quick start: warlock horizon feed list[/dim]")


@horizon.group("feed", invoke_without_command=True)
@click.pass_context
def horizon_feed(ctx: click.Context) -> None:
    """Regulatory feed management."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@horizon_feed.command("list")
def feed_list() -> None:
    """List configured regulatory feed sources."""
    from warlock.integrations.regulatory_feed import list_feeds

    feeds = list_feeds()

    table = Table(title="Regulatory Feed Sources")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Enabled")
    table.add_column("Frameworks")
    table.add_column("Description", style="dim")

    for f in feeds:
        enabled_style = "green" if f["enabled"] else "red"
        table.add_row(
            f["name"],
            f["type"],
            f"[{enabled_style}]{f['enabled']}[/{enabled_style}]",
            ", ".join(f["frameworks"][:3]),
            escape(f["description"][:50]),
        )

    console.print(table)
    console.print(f"\n[dim]{len(feeds)} feed sources configured[/dim]")


@horizon_feed.command("refresh")
@click.option("--source", "-s", default=None, help="Refresh a specific feed source by name")
def feed_refresh(source: str | None) -> None:
    """Refresh regulatory feeds and classify changes."""
    from warlock.integrations.regulatory_feed import DEFAULT_FEEDS, refresh_all_feeds, refresh_feed

    if source:
        matching = [f for f in DEFAULT_FEEDS if f.name == source]
        if not matching:
            console.print(f"[red]Feed source '{escape(source)}' not found.[/red]")
            return
        items = refresh_feed(matching[0])
    else:
        items = refresh_all_feeds()

    if not items:
        console.print("[dim]No items retrieved. Ensure httpx is installed: pip install httpx[/dim]")
        return

    table = Table(title=f"Regulatory Updates ({len(items)} items)")
    table.add_column("Source", style="cyan")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Frameworks")
    table.add_column("Published", style="dim")

    severity_styles = {
        "high": "red",
        "medium": "yellow",
        "low": "dim",
    }

    for item in items[:30]:
        sev_style = severity_styles.get(item.severity, "")
        sev_text = f"[{sev_style}]{item.severity}[/{sev_style}]" if sev_style else item.severity
        table.add_row(
            item.source[:20],
            escape(item.title[:60]),
            sev_text,
            ", ".join(item.affected_frameworks[:3]),
            item.published[:20] if item.published else "",
        )

    console.print(table)
    if len(items) > 30:
        console.print(f"[dim]... and {len(items) - 30} more items[/dim]")
