"""Statement of Applicability (SoA) CLI command.

GAP-074: Exposes warlock/export/soa.py via the CLI.
"""

from __future__ import annotations

import json as _json

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.command("soa")
@click.option(
    "--system",
    "-s",
    "system_id",
    default=None,
    help="System profile ID or acronym (default: first available).",
)
@click.option("--output", "-o", "output_file", default=None, help="Write output to file.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format.",
)
def soa_cmd(system_id: str | None, output_file: str | None, fmt: str) -> None:
    """Generate ISO 27001 Statement of Applicability (SoA)."""
    from warlock.cli import _resolve_system_id
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import SystemProfile
    from warlock.export.soa import StatementOfApplicability

    init_db()

    with get_read_session() as session:
        if system_id:
            system_id = _resolve_system_id(session, system_id)
        else:
            sp = session.query(SystemProfile).first()
            if not sp:
                console.print("[yellow]No system profiles found. Run the pipeline first.[/yellow]")
                return
            system_id = sp.id

        soa = StatementOfApplicability()

        if fmt == "csv":
            content = soa.export_csv(session, system_id)
            if output_file:
                with open(output_file, "w") as f:
                    f.write(content)
                console.print(f"[green]SoA CSV written to {escape(output_file)}[/green]")
            else:
                console.print(content)
            return

        if fmt == "json":
            content = soa.export_json(session, system_id)
            if output_file:
                with open(output_file, "w") as f:
                    f.write(content)
                console.print(f"[green]SoA JSON written to {escape(output_file)}[/green]")
            else:
                console.print_json(content)
            return

        # Table format
        data = soa.generate(session, system_id)

        # Summary
        summary = data["summary"]
        console.print("\n[bold]ISO 27001 Statement of Applicability[/bold]")
        console.print(
            f"System: {escape(data['system_profile']['name'])} "
            f"({escape(data['system_profile'].get('acronym', ''))})"
        )
        console.print(
            f"Total: {summary['total_controls']}  "
            f"Applicable: {summary['applicable']}  "
            f"Implemented: {summary['implemented']}  "
            f"Not Applicable: {summary['not_applicable']}\n"
        )

        table = Table(title="SoA Entries")
        table.add_column("Control ID", style="cyan", min_width=10)
        table.add_column("Family", max_width=12)
        table.add_column("Title", max_width=35)
        table.add_column("Applicable", justify="center")
        table.add_column("Status", min_width=14)
        table.add_column("Justification", max_width=40)

        for entry in data["entries"]:
            status = entry["implementation_status"]
            if status == "Implemented":
                style = "[green]Implemented[/green]"
            elif status == "Not Implemented":
                style = "[red]Not Implemented[/red]"
            elif status == "Partially Implemented":
                style = "[yellow]Partial[/yellow]"
            elif status == "Not Applicable":
                style = "[dim]N/A[/dim]"
            else:
                style = "[dim]Not Assessed[/dim]"

            justification = entry.get("justification") or entry.get("exclusion_justification", "")

            table.add_row(
                entry["control_id"],
                entry["family"],
                escape(entry["title"][:35]),
                "[green]Yes[/green]" if entry["applicable"] else "[dim]No[/dim]",
                style,
                escape((justification or "")[:40]),
            )

        console.print(table)

        if output_file:
            with open(output_file, "w") as f:
                _json.dump(data, f, indent=2, default=str)
            console.print(f"\n[green]SoA data written to {escape(output_file)}[/green]")
