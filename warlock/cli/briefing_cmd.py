"""CLI command: warlock briefing — cross-domain daily priority view."""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.panel import Panel
from rich.table import Table

from warlock.cli import cli, console


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--owner", default=None, help="Filter by assignee")
@click.option(
    "--mode",
    default="steady-state",
    type=click.Choice(["steady-state", "audit-prep", "remediation-sprint", "incident-response"]),
    help="Operational mode",
)
@click.option("--limit", "-n", default=30, help="Max items per section")
def briefing(framework, owner, mode, limit):
    """Daily briefing — what needs attention across all domains."""
    from warlock.db.engine import get_session
    from warlock.domains.base import QueryFilters
    from warlock.domains.registry import DomainRegistry
    from warlock.domains.controls import ControlsDomainService
    from warlock.domains.issues import IssuesDomainService
    from warlock.domains.evidence import EvidenceDomainService

    now = datetime.now(timezone.utc)
    filters = QueryFilters(
        frameworks=[framework] if framework else None,
        owner=owner,
        mode=mode,
        limit=limit,
    )

    with get_session() as session:
        registry = DomainRegistry()
        registry.register(ControlsDomainService(session))
        registry.register(IssuesDomainService(session))
        registry.register(EvidenceDomainService(session))
        items = registry.get_briefing(filters)

    fw_label = f" — {framework}" if framework else ""
    console.print(
        Panel(
            f"[bold]Warlock Daily Briefing[/bold] — {now.strftime('%Y-%m-%d')} (mode: {mode}){fw_label}",
            style="cyan",
        )
    )

    if not items:
        console.print("[dim]Nothing urgent. All clear.[/dim]")
        return

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda i: (sev_order.get(i.severity, 5), -i.priority_score))

    sev_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }

    table = Table(show_header=True, show_lines=False, pad_edge=False)
    table.add_column("Sev", style="bold", max_width=8)
    table.add_column("Domain", style="dim", max_width=10)
    table.add_column("Summary", min_width=40)
    table.add_column("Action", style="cyan", max_width=40)

    for item in items[:limit]:
        sev_style = sev_colors.get(item.severity, "")
        table.add_row(
            f"[{sev_style}]{item.severity.upper()[:4]}[/{sev_style}]",
            item.domain,
            item.summary[:80],
            item.action_hint,
        )

    console.print(table)
    console.print(f"\n[dim]{len(items)} items total. Use -f/--owner/--mode to filter.[/dim]")
