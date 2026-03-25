"""CLI commands for the data lake."""

from __future__ import annotations

from pathlib import Path

import click

from warlock.cli import cli, console, _error


def _safe_lake_path(path: str) -> str:
    """Validate a lake path is safe for SQL interpolation.

    Lake paths are interpolated into DuckDB ``read_parquet()`` calls.
    This guard rejects paths containing characters that could break out
    of the single-quoted SQL string literal (``'``, ``;``, ``--``).
    """
    if "'" in path or ";" in path or "--" in path:
        raise ValueError(f"Unsafe characters in lake path: {path!r}")
    return path


@cli.group(invoke_without_command=True)
@click.pass_context
def lake(ctx: click.Context) -> None:
    """Data lake management commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


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
    console.print(
        "\n[dim]Next: run [bold]warlock lake backfill[/bold] to populate the lake "
        "from existing pipeline data.[/dim]"
    )


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
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        _error(
            "pyarrow is required for lake operations but not installed.\n"
            "Install it with: pip install 'warlock[lake]'  or  pip install pyarrow"
        )

    from warlock.config import get_settings
    from warlock.db.engine import get_session
    from warlock.lake.backfill import backfill

    settings = get_settings()
    lake_path = path or settings.lake_path

    # Ensure lake directories exist
    for zone in [
        "raw",
        "enrichment",
        "curated/control_results",
        "curated/control_mappings",
        "curated/connector_runs",
    ]:
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
        console.print(
            f"\n[red]Reconciliation FAILED — {len(result.drifted)} table(s) exceed threshold.[/red]"
        )
        raise SystemExit(1)


@lake.command("aggregate")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def lake_aggregate(path: str | None) -> None:
    """Refresh materialized aggregation tables."""
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        _error(
            "pyarrow is required for lake operations but not installed.\n"
            'Install it with: pip install -e ".[lake]"'
        )

    from warlock.config import get_settings
    from warlock.lake.aggregations import refresh_aggregations

    settings = get_settings()
    lake_path = path or settings.lake_path

    console.print(f"[cyan]Refreshing aggregations: {lake_path}[/cyan]")
    counts = refresh_aggregations(lake_path)

    for table_name, count in counts.items():
        console.print(f"  {table_name}: {count} rows")

    if not counts:
        console.print(
            "[yellow]No data found in lake. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
    else:
        console.print("[green]Aggregation refresh complete.[/green]")


@lake.command("query")
@click.argument("question")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def lake_query(question: str, path: str | None) -> None:
    """Query the lake with a natural language question."""
    from warlock.config import get_settings
    from warlock.lake.ask import query_lake

    settings = get_settings()
    lake_path = path or settings.lake_path

    result = query_lake(lake_path, question)
    console.print(f"\n[cyan]{result['answer']}[/cyan]\n")


@lake.command("assess")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--framework", default=None, help="Limit to specific framework")
def lake_assess(path: str | None, framework: str | None) -> None:
    """Run batch aggregate control assessment from lake data."""
    try:
        import duckdb  # noqa: F401
    except ImportError:
        _error(
            "duckdb is required for lake operations but not installed.\n"
            'Install it with: pip install -e ".[lake]"'
        )

    from collections import Counter

    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.batch_assessor import aggregate_control_statuses, write_aggregate_assessments

    settings = get_settings()
    lake_path = path or settings.lake_path

    console.print("[cyan]Computing aggregate control assessments...[/cyan]")
    aggregates = aggregate_control_statuses(lake_path)

    if framework:
        aggregates = [a for a in aggregates if a["framework"] == framework]

    if not aggregates:
        console.print("[yellow]No control results found in lake.[/yellow]")
        return

    written = write_aggregate_assessments(lake_path, aggregates)

    table = Table(title=f"Aggregate Control Assessments ({written} total)")
    table.add_column("Framework")
    table.add_column("Controls", justify="right")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-Compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")

    by_fw: dict[str, Counter] = {}
    for a in aggregates:
        fw = a["framework"]
        if fw not in by_fw:
            by_fw[fw] = Counter()
        by_fw[fw][a["aggregate_status"]] += 1

    for fw in sorted(by_fw):
        c = by_fw[fw]
        table.add_row(
            fw,
            str(sum(c.values())),
            str(c.get("compliant", 0)),
            str(c.get("non_compliant", 0)),
            str(c.get("partial", 0)),
        )
    console.print(table)
    console.print(f"[green]{written} aggregate assessments written.[/green]")


# ---------------------------------------------------------------------------
# Evidence Commands
# ---------------------------------------------------------------------------


@lake.group(invoke_without_command=True)
@click.pass_context
def evidence(ctx: click.Context) -> None:
    """Evidence management commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@evidence.command("list")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--limit", default=20, type=int, help="Maximum rows to display")
def evidence_list(path: str | None, limit: int) -> None:
    """List evidence artifacts from the lake."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "evidence_artifacts" / "**" / "*.parquet"))

    if not list(base.glob("curated/evidence_artifacts/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT id, source_connector, artifact_type, collected_at FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
            [limit],
        )
        table = Table(title="Evidence Artifacts")
        for col in ["id", "source_connector", "artifact_type", "collected_at"]:
            table.add_column(col, style="cyan" if col == "source_connector" else None)
        for row in result:
            table.add_row(
                str(row.get("id", "")),
                str(row.get("source_connector", "")),
                str(row.get("artifact_type", "")),
                str(row.get("collected_at", "")),
            )
        console.print(table)
    finally:
        engine.close()


@evidence.command("freshness")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def evidence_freshness(path: str | None) -> None:
    """Show evidence freshness status."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "evidence_freshness" / "**" / "*.parquet"))

    if not list(base.glob("curated/evidence_freshness/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
            [],
        )
        table = Table(title="Evidence Freshness")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


# ---------------------------------------------------------------------------
# Incident Commands
# ---------------------------------------------------------------------------


@lake.group(invoke_without_command=True)
@click.pass_context
def incidents(ctx: click.Context) -> None:
    """Incident management commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@incidents.command("list")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--status", default=None, help="Filter by status")
@click.option("--limit", default=20, type=int, help="Maximum rows to display")
def incidents_list(path: str | None, status: str | None, limit: int) -> None:
    """List incidents from the lake."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "incidents" / "**" / "*.parquet"))

    if not list(base.glob("curated/incidents/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        if status:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) WHERE status = ? LIMIT ?",
                [status, limit],
            )
        else:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
                [limit],
            )
        table = Table(title="Incidents")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@incidents.command("events")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--severity", default=None, help="Filter by severity")
@click.option("--limit", default=20, type=int, help="Maximum rows to display")
def incidents_events(path: str | None, severity: str | None, limit: int) -> None:
    """List security events."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "security_events" / "**" / "*.parquet"))

    if not list(base.glob("curated/security_events/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        if severity:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) WHERE severity = ? LIMIT ?",
                [severity, limit],
            )
        else:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
                [limit],
            )
        table = Table(title="Security Events")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


# ---------------------------------------------------------------------------
# Privacy Commands
# ---------------------------------------------------------------------------


@lake.group(invoke_without_command=True)
@click.pass_context
def privacy(ctx: click.Context) -> None:
    """Privacy management commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@privacy.command("dsars")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--status", default=None, help="Filter by status")
def privacy_dsars(path: str | None, status: str | None) -> None:
    """List DSAR requests."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "dsars" / "**" / "*.parquet"))

    if not list(base.glob("curated/dsars/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        if status:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) WHERE status = ?",
                [status],
            )
        else:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
        table = Table(title="DSAR Requests")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@privacy.command("processing")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def privacy_processing(path: str | None) -> None:
    """List processing activities (GDPR Art. 30)."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "processing_activities" / "**" / "*.parquet"))

    if not list(base.glob("curated/processing_activities/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
            [],
        )
        table = Table(title="Processing Activities (GDPR Art. 30)")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@privacy.command("transfers")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def privacy_transfers(path: str | None) -> None:
    """List cross-border data transfers."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "data_transfers" / "**" / "*.parquet"))

    if not list(base.glob("curated/data_transfers/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
            [],
        )
        table = Table(title="Cross-Border Data Transfers")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


# ---------------------------------------------------------------------------
# Supply Chain Commands
# ---------------------------------------------------------------------------


@lake.group(invoke_without_command=True)
@click.pass_context
def supply_chain(ctx: click.Context) -> None:
    """Supply chain risk commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@supply_chain.command("sbom")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--limit", default=50, type=int, help="Maximum rows to display")
def supply_chain_sbom(path: str | None, limit: int) -> None:
    """List SBOM components."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "sbom_components" / "**" / "*.parquet"))

    if not list(base.glob("curated/sbom_components/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
            [limit],
        )
        table = Table(title="SBOM Components")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@supply_chain.command("suppliers")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def supply_chain_suppliers(path: str | None) -> None:
    """List supplier assessments."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "supplier_assessments" / "**" / "*.parquet"))

    if not list(base.glob("curated/supplier_assessments/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
            [],
        )
        table = Table(title="Supplier Assessments")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@supply_chain.command("concentration")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def supply_chain_concentration(path: str | None) -> None:
    """Show concentration risk analysis."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "concentration_risk" / "**" / "*.parquet"))

    if not list(base.glob("curated/concentration_risk/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
            [],
        )
        table = Table(title="Concentration Risk")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


# ---------------------------------------------------------------------------
# Analytics Commands
# ---------------------------------------------------------------------------


@lake.group(invoke_without_command=True)
@click.pass_context
def analytics(ctx: click.Context) -> None:
    """Analytics and trend commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@analytics.command("trends")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--framework", default=None, help="Limit to specific framework")
def analytics_trends(path: str | None, framework: str | None) -> None:
    """Show compliance posture trends."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "agg_framework_posture" / "**" / "*.parquet"))

    if not list(base.glob("curated/agg_framework_posture/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        if framework:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) WHERE framework = ?",
                [framework],
            )
        else:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
        table = Table(title="Compliance Posture Trends")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@analytics.command("heatmap")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--framework", default=None, help="Limit to specific framework")
def analytics_heatmap(path: str | None, framework: str | None) -> None:
    """Show control family compliance heatmap."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(
        str(base / "curated" / "agg_control_family_posture" / "**" / "*.parquet")
    )

    if not list(base.glob("curated/agg_control_family_posture/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        if framework:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) WHERE framework = ?",
                [framework],
            )
        else:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
        table = Table(title="Control Family Compliance Heatmap")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


# ---------------------------------------------------------------------------
# Pipeline Health Commands
# ---------------------------------------------------------------------------


@lake.group(invoke_without_command=True)
@click.pass_context
def health(ctx: click.Context) -> None:
    """Pipeline health commands."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@health.command("runs")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--limit", default=10, type=int, help="Maximum rows to display")
def health_runs(path: str | None, limit: int) -> None:
    """Show recent pipeline runs."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "pipeline_runs" / "**" / "*.parquet"))

    if not list(base.glob("curated/pipeline_runs/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
            [limit],
        )
        table = Table(title="Recent Pipeline Runs")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@health.command("freshness")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def health_freshness(path: str | None) -> None:
    """Show data freshness per connector."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "data_freshness" / "**" / "*.parquet"))

    if not list(base.glob("curated/data_freshness/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
            [],
        )
        table = Table(title="Data Freshness per Connector")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


@health.command("coverage")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def health_coverage(path: str | None) -> None:
    """Show data coverage metrics."""
    from rich.table import Table

    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    lake_path = path or settings.lake_path
    base = Path(lake_path)
    glob = _safe_lake_path(str(base / "curated" / "coverage_metrics" / "**" / "*.parquet"))

    if not list(base.glob("curated/coverage_metrics/**/*.parquet")):
        console.print(
            "[yellow]No data found. Run pipeline with WLK_LAKE_ENABLED=true first.[/yellow]"
        )
        return

    engine = LakeQueryEngine(lake_path)
    try:
        result = engine.query(
            f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
            [],
        )
        table = Table(title="Data Coverage Metrics")
        if result:
            for col in result[0].keys():
                table.add_column(col)
            for row in result:
                table.add_row(*[str(v) for v in row.values()])
        console.print(table)
    finally:
        engine.close()


# ---------------------------------------------------------------------------
# Maintenance Commands
# ---------------------------------------------------------------------------


@lake.command("register")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def lake_register(path: str | None) -> None:
    """Register lake tables with the Iceberg catalog."""
    try:
        import pyiceberg  # noqa: F401
    except ImportError:
        _error(
            "pyiceberg is required for lake operations but not installed.\n"
            'Install it with: pip install -e ".[lake]"'
        )

    from warlock.config import get_settings
    from warlock.lake.catalog import register_pipeline_tables

    settings = get_settings()
    lake_path = path or settings.lake_path
    console.print("[cyan]Registering tables with Iceberg catalog...[/cyan]")
    results = register_pipeline_tables(lake_path)
    for table, status in results.items():
        style = "green" if status == "registered" else "yellow"
        console.print(f"  [{style}]{table}: {status}[/{style}]")


@lake.command("compact")
@click.option("--path", default=None)
@click.option("--target-size", default=256, type=int, help="Target file size in MB")
def lake_compact(path: str | None, target_size: int) -> None:
    """Compact small Parquet files into larger ones."""
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        _error(
            "pyarrow is required for lake operations but not installed.\n"
            'Install it with: pip install -e ".[lake]"'
        )

    from warlock.config import get_settings
    from warlock.lake.maintenance import compact

    settings = get_settings()
    lake_path = path or settings.lake_path
    stats = compact(lake_path, target_size_mb=target_size)
    if stats:
        for zone, count in stats.items():
            console.print(f"  Compacted {count} files in {zone}")
    else:
        console.print("[dim]No compaction needed.[/dim]")


@lake.command("maintenance")
@click.option("--path", default=None)
def lake_maintenance(path: str | None) -> None:
    """Run all lake maintenance jobs (compact, expire, cleanup)."""
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        _error(
            "pyarrow is required for lake operations but not installed.\n"
            'Install it with: pip install -e ".[lake]"'
        )

    from warlock.config import get_settings
    from warlock.lake.maintenance import run_all_maintenance

    settings = get_settings()
    lake_path = path or settings.lake_path
    console.print(f"[cyan]Running maintenance on {lake_path}...[/cyan]")
    results = run_all_maintenance(lake_path)
    for job, stats in results.items():
        if stats:
            console.print(f"  [green]{job}:[/green] {stats}")
        else:
            console.print(f"  [dim]{job}: nothing to do[/dim]")
    console.print("[green]Maintenance complete.[/green]")


@lake.command("thin-oltp")
@click.option("--dry-run/--no-dry-run", default=True, help="Count only, don't delete")
@click.confirmation_option(prompt="This will remove historical records from OLTP. Continue?")
def lake_thin_oltp(dry_run: bool) -> None:
    """Remove historical records from OLTP (keep latest per control only)."""
    from warlock.db.engine import get_session
    from warlock.lake.oltp_thin import thin_oltp

    with get_session() as session:
        stats = thin_oltp(session, dry_run=dry_run)
        if not dry_run:
            session.commit()

    action = "Would remove" if dry_run else "Removed"
    console.print(f"\n  Control results kept:    {stats.control_results_kept}")
    console.print(f"  Control results {action.lower()}: {stats.control_results_removed}")
    console.print(f"  Mappings {action.lower()}:         {stats.control_mappings_removed}")
    console.print(f"  Findings {action.lower()}:         {stats.findings_removed}")
    console.print(f"  Raw events {action.lower()}:       {stats.raw_events_removed}")
    console.print(f"  Total {action.lower()}:            {stats.total_removed}")

    if dry_run:
        console.print("\n[yellow]Dry run — no changes made. Use --no-dry-run to execute.[/yellow]")


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
