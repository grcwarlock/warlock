"""Supply chain CLI commands.

SBOM import, VEX document processing, and supply chain risk analysis.
"""

from __future__ import annotations

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.group("supply-chain", invoke_without_command=True)
@click.pass_context
def supply_chain(ctx: click.Context) -> None:
    """Supply chain risk management -- SBOM and VEX processing."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        console.print("\n[dim]Quick start: warlock supply-chain import-sbom <file>[/dim]")


@supply_chain.command("import-sbom")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--format", "fmt", default=None, help="Force format: cyclonedx, spdx (auto-detect)")
def import_sbom(file_path: str, fmt: str | None) -> None:
    """Import and analyze an SBOM file (CycloneDX or SPDX JSON)."""
    from warlock.workflows.supply_chain import (
        assess_license_risk,
        parse_cyclonedx,
        parse_sbom,
        parse_spdx,
    )

    with open(file_path) as fh:
        content = fh.read()

    import json

    if fmt == "cyclonedx":
        analysis = parse_cyclonedx(json.loads(content))
    elif fmt == "spdx":
        analysis = parse_spdx(json.loads(content))
    else:
        analysis = parse_sbom(content)

    # Summary
    console.print(f"\n[bold]SBOM Analysis -- {escape(file_path)}[/bold]")
    console.print(f"  Format:               {analysis.format}")
    console.print(f"  Spec Version:         {analysis.spec_version}")
    console.print(f"  Total Components:     {analysis.total_components}")
    console.print(f"  Vulnerable:           {analysis.vulnerable_components}")
    console.print(f"  Supplier Coverage:    {analysis.supplier_coverage:.0%}")

    # Components table (top 20)
    if analysis.components:
        table = Table(title=f"Components ({len(analysis.components)} total, showing top 20)")
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Supplier")
        table.add_column("Licenses")
        table.add_column("Vulns", justify="right")

        for comp in analysis.components[:20]:
            vuln_count = len(comp.vulnerabilities)
            vuln_style = "red" if vuln_count > 0 else "green"
            table.add_row(
                escape(comp.name[:40]),
                escape(comp.version[:15]),
                escape(comp.supplier[:25]) if comp.supplier else "[dim]unknown[/dim]",
                ", ".join(comp.licenses[:2]) or "[dim]none[/dim]",
                f"[{vuln_style}]{vuln_count}[/{vuln_style}]",
            )
        console.print(table)
        if len(analysis.components) > 20:
            console.print(f"[dim]... and {len(analysis.components) - 20} more[/dim]")

    # License risks
    risks = assess_license_risk(analysis)
    if risks:
        console.print(f"\n[yellow]License Risks ({len(risks)}):[/yellow]")
        for risk in risks[:10]:
            sev = risk.get("severity", "medium")
            sev_style = "red" if sev == "high" else "yellow"
            console.print(
                f"  [{sev_style}]{sev}[/{sev_style}] "
                f"{escape(risk['component'])} -- {escape(risk['description'])}"
            )
        if len(risks) > 10:
            console.print(f"  [dim]... and {len(risks) - 10} more[/dim]")


@supply_chain.command("vex")
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--apply-to", default=None, type=click.Path(exists=True), help="SBOM file to apply VEX to"
)
def vex_cmd(file_path: str, apply_to: str | None) -> None:
    """Parse a VEX document and optionally apply it to an SBOM."""
    from warlock.workflows.supply_chain import apply_vex_to_sbom, parse_sbom, parse_vex

    with open(file_path) as fh:
        vex_content = fh.read()

    vex = parse_vex(vex_content)

    console.print(f"\n[bold]VEX Document -- {escape(file_path)}[/bold]")
    console.print(f"  Format:               {vex.format}")
    console.print(f"  Document ID:          {vex.doc_id or 'n/a'}")
    console.print(f"  Total Statements:     {vex.total_statements}")
    console.print(f"  Not Affected:         [green]{vex.not_affected_count}[/green]")
    console.print(f"  Affected:             [red]{vex.affected_count}[/red]")
    console.print(f"  Fixed:                [green]{vex.fixed_count}[/green]")
    console.print(f"  Under Investigation:  [yellow]{vex.under_investigation_count}[/yellow]")

    # Statement details
    if vex.statements:
        table = Table(title="VEX Statements")
        table.add_column("Vulnerability", style="cyan")
        table.add_column("Status")
        table.add_column("Justification")
        table.add_column("Product")

        status_styles = {
            "not_affected": "green",
            "fixed": "green",
            "affected": "red",
            "under_investigation": "yellow",
        }

        for stmt in vex.statements[:20]:
            style = status_styles.get(stmt.status, "")
            status_text = f"[{style}]{stmt.status}[/{style}]" if style else stmt.status
            table.add_row(
                escape(stmt.vulnerability_id[:30]),
                status_text,
                escape(stmt.justification[:30]) if stmt.justification else "",
                escape(stmt.product[:30]) if stmt.product else "",
            )
        console.print(table)
        if len(vex.statements) > 20:
            console.print(f"[dim]... and {len(vex.statements) - 20} more[/dim]")

    # Apply to SBOM if requested
    if apply_to:
        with open(apply_to) as fh:
            sbom_content = fh.read()
        sbom = parse_sbom(sbom_content)
        result = apply_vex_to_sbom(sbom, vex)

        console.print("\n[bold]VEX Application Results:[/bold]")
        console.print(f"  Statements applied:              {result['vex_statements_applied']}")
        console.print(
            f"  Original vulnerable components:  {result['original_vulnerable_components']}"
        )
        console.print(
            f"  Remaining vulnerable components: {result['remaining_vulnerable_components']}"
        )
        console.print(
            f"  Components cleared:              [green]{result['components_cleared']}[/green]"
        )
