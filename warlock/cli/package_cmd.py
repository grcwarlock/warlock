"""CLI command for packaging offline compliance bundles.

``warlock package --offline`` creates a ZIP manifest containing all
frameworks, OPA policies, and OSCAL catalogs for air-gapped deployment.
"""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console


@cli.command("package")
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Create offline bundle with all frameworks, policies, and OSCAL catalogs",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file path (default: warlock-bundle-<date>.zip)",
)
@click.option(
    "--frameworks-only",
    is_flag=True,
    default=False,
    help="Include only framework YAMLs (skip policies and OSCAL)",
)
def package_cmd(offline: bool, output: str | None, frameworks_only: bool) -> None:
    """Package compliance artifacts for offline or air-gapped deployment.

    Creates a ZIP bundle containing framework definitions, OPA/Rego
    policies, and OSCAL catalog/profile JSON files.
    """
    if not offline:
        console.print(
            "[dim]Use --offline to create an offline compliance bundle.[/dim]\n"
            "[dim]Example: warlock package --offline -o bundle.zip[/dim]"
        )
        return

    project_root = Path(__file__).resolve().parent.parent.parent

    # Collect artifacts
    artifacts: list[tuple[str, Path]] = []

    # Framework YAMLs
    fw_dir = project_root / "warlock" / "frameworks"
    if fw_dir.is_dir():
        for f in sorted(fw_dir.glob("*.yaml")):
            artifacts.append((f"frameworks/{f.name}", f))

    if not frameworks_only:
        # OPA policies
        policies_dir = project_root / "policies"
        if policies_dir.is_dir():
            for f in sorted(policies_dir.rglob("*.rego")):
                rel = f.relative_to(policies_dir)
                artifacts.append((f"policies/{rel}", f))

        # OSCAL catalogs/profiles
        oscal_dir = project_root / "frameworks-oscal"
        if oscal_dir.is_dir():
            for f in sorted(oscal_dir.rglob("*.json")):
                rel = f.relative_to(oscal_dir)
                artifacts.append((f"oscal/{rel}", f))

    if not artifacts:
        console.print("[red]No artifacts found to package.[/red]")
        return

    # Determine output path
    if output is None:
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        output = f"warlock-bundle-{date_str}.zip"

    # Build manifest
    manifest = {
        "bundle_version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact_count": len(artifacts),
        "contents": {},
    }

    # Count by category
    categories: dict[str, int] = {}
    for arc_path, _ in artifacts:
        cat = arc_path.split("/")[0]
        categories[cat] = categories.get(cat, 0) + 1
    manifest["contents"] = categories

    # Create ZIP
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        # Write manifest
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        # Write artifacts
        for arc_path, file_path in artifacts:
            zf.write(file_path, arc_path)

    # Report
    file_size = os.path.getsize(output)
    size_mb = file_size / (1024 * 1024)

    console.print(f"\n[green]Offline bundle created:[/green] {escape(output)}")
    console.print(f"  Size: {size_mb:.1f} MB")

    table = Table(title="Bundle Contents")
    table.add_column("Category", style="cyan")
    table.add_column("Files", justify="right")

    for cat, count in sorted(categories.items()):
        table.add_row(cat, str(count))
    table.add_row("[bold]Total[/bold]", f"[bold]{len(artifacts)}[/bold]")

    console.print(table)
