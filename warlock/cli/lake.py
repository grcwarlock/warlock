"""CLI commands for the data lake."""

from __future__ import annotations

from pathlib import Path

import click

from warlock.cli import cli, console


@cli.group()
def lake() -> None:
    """Data lake management commands."""


@lake.command("init")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def lake_init(path: str | None) -> None:
    """Create lake directory structure (raw/enrichment/curated zones)."""
    from warlock.config import get_settings

    settings = get_settings()
    lake_path = Path(path or settings.lake_path)

    zones = [
        lake_path / "raw",
        lake_path / "enrichment",
        lake_path / "curated" / "control_results",
        lake_path / "curated" / "control_mappings",
        lake_path / "curated" / "connector_runs",
    ]

    for zone in zones:
        zone.mkdir(parents=True, exist_ok=True)

    console.print(f"[green]Lake initialized at {lake_path}[/green]")
    for zone in zones:
        console.print(f"  {zone}")


@lake.command("status")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def lake_status(path: str | None) -> None:
    """Show lake status (zones, file counts, total size)."""
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = Path(path or settings.lake_path)

    if not lake_path.exists():
        console.print(f"[yellow]Lake directory does not exist: {lake_path}[/yellow]")
        console.print("[dim]Run 'warlock lake init' to create it.[/dim]")
        return

    table = Table(title=f"Lake Status: {lake_path}")
    table.add_column("Zone", style="cyan")
    table.add_column("Files", justify="right")
    table.add_column("Size", justify="right")

    zones = {
        "raw": "raw",
        "enrichment": "enrichment",
        "curated/control_results": "curated/control_results",
        "curated/control_mappings": "curated/control_mappings",
        "curated/connector_runs": "curated/connector_runs",
    }

    total_files = 0
    total_size = 0

    for label, subpath in zones.items():
        zone_dir = lake_path / subpath
        if not zone_dir.exists():
            table.add_row(label, "0", "0 B")
            continue

        files = list(zone_dir.rglob("*.parquet"))
        size = sum(f.stat().st_size for f in files)
        total_files += len(files)
        total_size += size
        table.add_row(label, str(len(files)), _format_size(size))

    table.add_row("---", "---", "---")
    table.add_row("[bold]Total[/bold]", str(total_files), _format_size(total_size))

    console.print(table)
    console.print(f"\n  Lake enabled: {settings.lake_enabled}")


@lake.command("backfill")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--batch-size", default=10000, help="Rows per batch")
def lake_backfill(path: str | None, batch_size: int) -> None:
    """Backfill historical OLTP data to the lake."""
    from warlock.config import get_settings
    from warlock.db.engine import get_session
    from warlock.lake.backfill import backfill

    settings = get_settings()
    lake_path = path or settings.lake_path

    # Ensure lake directories exist
    for zone in ["raw", "enrichment", "curated/control_results", "curated/control_mappings", "curated/connector_runs"]:
        (Path(lake_path) / zone).mkdir(parents=True, exist_ok=True)

    console.print(f"[cyan]Backfilling OLTP data to lake: {lake_path}[/cyan]")

    with get_session() as session:
        stats = backfill(session, lake_path, batch_size=batch_size)

    from rich.table import Table

    table = Table(title="Backfill Results")
    table.add_column("Table", style="cyan")
    table.add_column("Rows Written", justify="right")
    table.add_row("Raw events", str(stats.raw_events))
    table.add_row("Findings", str(stats.findings))
    table.add_row("Control mappings", str(stats.control_mappings))
    table.add_row("Control results", str(stats.control_results))
    table.add_row("Connector runs", str(stats.connector_runs))
    table.add_row("---", "---")
    table.add_row("[bold]Total[/bold]", str(stats.total))
    table.add_row("Duration", f"{stats.duration_seconds:.2f}s")
    console.print(table)

    if stats.errors:
        console.print(f"\n[red]Errors ({len(stats.errors)}):[/red]")
        for err in stats.errors:
            console.print(f"  [dim]{err}[/dim]")
        raise SystemExit(1)

    console.print("[green]Backfill complete.[/green]")


@lake.command("reconcile")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--threshold", default=0.001, help="Max acceptable drift (default: 0.1%%)")
def lake_reconcile(path: str | None, threshold: float) -> None:
    """Compare OLTP row counts with lake row counts."""
    from warlock.config import get_settings
    from warlock.db.engine import get_session
    from warlock.lake.reconciliation import reconcile

    settings = get_settings()
    lake_path = path or settings.lake_path

    with get_session() as session:
        result = reconcile(session, lake_path, threshold=threshold)

    from rich.table import Table

    table = Table(title="OLTP vs Lake Reconciliation")
    table.add_column("Table", style="cyan")
    table.add_column("OLTP", justify="right")
    table.add_column("Lake", justify="right")
    table.add_column("Drift", justify="right")
    table.add_column("Status")

    for comp in result.comparisons:
        status_style = "green" if comp.drift <= result.threshold else "red"
        status_label = "OK" if comp.drift <= result.threshold else "DRIFT"
        drift_str = f"{comp.drift_pct:.2f}%"
        table.add_row(
            comp.table,
            str(comp.oltp_count),
            str(comp.lake_count),
            drift_str,
            f"[{status_style}]{status_label}[/]",
        )

    console.print(table)

    if result.passed:
        console.print(f"\n[green]Reconciliation passed (threshold={threshold * 100:.1f}%).[/green]")
    else:
        console.print(f"\n[red]Reconciliation FAILED — {len(result.drifted)} table(s) exceed threshold.[/red]")
        raise SystemExit(1)


@lake.command("aggregate")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def lake_aggregate(path: str | None) -> None:
    """Refresh materialized aggregation tables."""
    from warlock.config import get_settings
    from warlock.lake.aggregations import refresh_aggregations

    settings = get_settings()
    lake_path = path or settings.lake_path

    console.print(f"[cyan]Refreshing aggregations: {lake_path}[/cyan]")
    counts = refresh_aggregations(lake_path)

    for table_name, count in counts.items():
        console.print(f"  {table_name}: {count} rows")

    if not counts:
        console.print("[yellow]No data found in lake. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]")
    else:
        console.print("[green]Aggregation refresh complete.[/green]")


def _format_size(size_bytes: int) -> str:
    """Format bytes as human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
