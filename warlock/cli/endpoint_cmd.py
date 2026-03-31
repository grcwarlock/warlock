"""CLI commands for endpoint compliance agent reporting.

Provides ``warlock connectors agent-report`` for viewing and managing
endpoint compliance telemetry from MDM/EDR agents.
"""

from __future__ import annotations

import json

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console

# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("endpoint", invoke_without_command=True)
@click.pass_context
def endpoint(ctx: click.Context) -> None:
    """Endpoint compliance agent management."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        console.print("\n[dim]Quick start: warlock endpoint agent-report[/dim]")


# ---------------------------------------------------------------------------
# agent-report — show endpoint compliance status
# ---------------------------------------------------------------------------


@endpoint.command("agent-report")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def agent_report(output_format: str) -> None:
    """Show endpoint compliance reports from agent telemetry.

    Displays device compliance posture including encryption, AV,
    firewall, and patch status for all reported endpoints.
    """
    from warlock.connectors.base import ConnectorConfig, SourceType
    from warlock.connectors.endpoint_agent import (
        EndpointAgentConnector,
        EndpointComplianceReport,
    )

    config = ConnectorConfig(
        name="endpoint_agent",
        source_type=SourceType.MDM,
        provider="endpoint_agent",
    )
    connector = EndpointAgentConnector(config)
    result = connector.collect()

    if not result.events:
        console.print("[dim]No endpoint reports collected.[/dim]")
        return

    reports = [EndpointComplianceReport.from_dict(e.raw_data) for e in result.events]

    if output_format == "json":
        import dataclasses

        data = [dataclasses.asdict(r) for r in reports]
        console.print(json.dumps(data, indent=2, default=str))
        return

    # Table output
    table = Table(title=f"Endpoint Compliance ({len(reports)} devices)")
    table.add_column("Hostname", style="cyan")
    table.add_column("OS")
    table.add_column("Encrypted", justify="center")
    table.add_column("AV", justify="center")
    table.add_column("Firewall", justify="center")
    table.add_column("Patch (days)", justify="right")
    table.add_column("Compliant", justify="center")
    table.add_column("Issues", style="dim")

    for r in reports:
        encrypted_icon = "[green]yes[/green]" if r.encrypted else "[red]no[/red]"
        av_icon = "[green]yes[/green]" if r.av_enabled else "[red]no[/red]"
        fw_icon = "[green]yes[/green]" if r.firewall_enabled else "[red]no[/red]"
        patch_style = "green" if r.patch_level <= 30 else "red"
        compliant_icon = "[green]PASS[/green]" if r.compliant else "[red]FAIL[/red]"
        issues_str = ", ".join(r.issues) if r.issues else "\u2014"

        table.add_row(
            escape(r.hostname),
            f"{escape(r.os)} {escape(r.os_version)}",
            encrypted_icon,
            av_icon,
            fw_icon,
            f"[{patch_style}]{r.patch_level}[/{patch_style}]",
            compliant_icon,
            escape(issues_str[:50]),
        )

    console.print(table)

    compliant_count = sum(1 for r in reports if r.compliant)
    console.print(
        f"\n[bold]Endpoint Posture:[/bold] "
        f"{compliant_count}/{len(reports)} compliant "
        f"({compliant_count / len(reports) * 100:.0f}%)"
    )
