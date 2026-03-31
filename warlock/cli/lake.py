"""CLI commands for the data lake."""

from __future__ import annotations

from pathlib import Path

import click

from warlock.cli import _error, cli, console


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
# OLTP fallback helper
# ---------------------------------------------------------------------------


def _has_lake_data(lake_path: str, zone: str) -> bool:
    """Check if a lake zone has Parquet data."""
    base = Path(lake_path)
    return bool(list(base.glob(f"{zone}/**/*.parquet")))


def _lake_or_oltp(lake_path: str, zone: str, lake_fn, oltp_fn) -> None:
    """Try lake query first; fall back to OLTP if no lake data exists."""
    if _has_lake_data(lake_path, zone):
        lake_fn(lake_path)
    else:
        console.print("[dim](Lake data unavailable -- showing OLTP data)[/dim]")
        oltp_fn()


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
    """List evidence artifacts (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "evidence_artifacts" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            result = engine.query(
                f"SELECT id, source_connector, artifact_type, collected_at "
                f"FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
                [limit],
            )
            table = Table(title="Evidence Artifacts (Lake)")
            for col in ["id", "source_connector", "artifact_type", "collected_at"]:
                table.add_column(col, style="cyan" if col == "source_connector" else None)
            for row in result:
                table.add_row(
                    *[
                        str(row.get(c, ""))
                        for c in ["id", "source_connector", "artifact_type", "collected_at"]
                    ]
                )
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import ControlResult
        from warlock.utils import ensure_aware

        init_db()
        with get_read_session() as session:
            rows = (
                session.query(ControlResult)
                .order_by(ControlResult.assessed_at.desc())
                .limit(limit)
                .all()
            )
        if not rows:
            console.print("[dim]No evidence records found.[/dim]")
            return
        table = Table(title="Evidence Artifacts (OLTP)")
        table.add_column("ID", style="dim")
        table.add_column("Framework", style="cyan")
        table.add_column("Control", style="cyan")
        table.add_column("Status")
        table.add_column("Assessed At")
        for r in rows:
            ts = ensure_aware(r.assessed_at).strftime("%Y-%m-%d %H:%M") if r.assessed_at else ""
            color = (
                "green"
                if r.status == "compliant"
                else "red"
                if r.status == "non_compliant"
                else "yellow"
            )
            table.add_row(
                r.id[:8],
                escape(r.framework),
                escape(r.control_id),
                f"[{color}]{escape(r.status)}[/{color}]",
                ts,
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/evidence_artifacts", _from_lake, _from_oltp)


@evidence.command("freshness")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def evidence_freshness(path: str | None) -> None:
    """Show evidence freshness status (lake with OLTP fallback)."""
    from datetime import datetime, timedelta, timezone

    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "evidence_freshness" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
            table = Table(title="Evidence Freshness (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import ControlResult
        from warlock.utils import ensure_aware

        init_db()
        now = datetime.now(timezone.utc)
        threshold_30 = now - timedelta(days=30)
        threshold_90 = now - timedelta(days=90)

        with get_read_session() as session:
            # Compute freshness per framework in Python (SQLite-safe)
            fw_stats: dict[str, dict] = {}
            all_rows = session.query(ControlResult.framework, ControlResult.assessed_at).all()
            for r in all_rows:
                fw = r.framework
                if fw not in fw_stats:
                    fw_stats[fw] = {"total": 0, "fresh": 0, "stale": 0, "expired": 0}
                fw_stats[fw]["total"] += 1
                if r.assessed_at:
                    assessed = ensure_aware(r.assessed_at)
                    if assessed >= threshold_30:
                        fw_stats[fw]["fresh"] += 1
                    elif assessed >= threshold_90:
                        fw_stats[fw]["stale"] += 1
                    else:
                        fw_stats[fw]["expired"] += 1

        if not fw_stats:
            console.print("[dim]No evidence records found.[/dim]")
            return

        table = Table(title="Evidence Freshness (OLTP)")
        table.add_column("Framework", style="cyan")
        table.add_column("Total", justify="right")
        table.add_column("Fresh (<30d)", justify="right", style="green")
        table.add_column("Stale (30-90d)", justify="right", style="yellow")
        table.add_column("Expired (>90d)", justify="right", style="red")
        for fw in sorted(fw_stats):
            s = fw_stats[fw]
            table.add_row(fw, str(s["total"]), str(s["fresh"]), str(s["stale"]), str(s["expired"]))
        console.print(table)

    _lake_or_oltp(lake_path, "curated/evidence_freshness", _from_lake, _from_oltp)


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
    """List incidents (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "incidents" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            if status:
                result = engine.query(
                    f"SELECT * FROM read_parquet('{glob}', union_by_name=true) "
                    f"WHERE status = ? LIMIT ?",
                    [status, limit],
                )
            else:
                result = engine.query(
                    f"SELECT * FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
                    [limit],
                )
            table = Table(title="Incidents (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import Finding
        from warlock.utils import ensure_aware

        init_db()
        with get_read_session() as session:
            q = session.query(Finding).filter(
                Finding.observation_type.in_(["alert", "policy_violation", "access_anomaly"])
            )
            if status:
                q = q.filter(Finding.severity == status)
            rows = q.order_by(Finding.ingested_at.desc()).limit(limit).all()

        if not rows:
            console.print("[dim]No incident-type findings found.[/dim]")
            return
        table = Table(title="Incidents (OLTP -- from findings)")
        table.add_column("ID", style="dim")
        table.add_column("Title")
        table.add_column("Type", style="cyan")
        table.add_column("Severity")
        table.add_column("Provider")
        table.add_column("Ingested")
        for r in rows:
            ts = ensure_aware(r.ingested_at).strftime("%Y-%m-%d %H:%M") if r.ingested_at else ""
            sev_color = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(
                r.severity, "dim"
            )
            table.add_row(
                r.id[:8],
                escape(r.title[:60] if r.title else ""),
                escape(r.observation_type),
                f"[{sev_color}]{escape(r.severity)}[/{sev_color}]",
                escape(r.provider),
                ts,
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/incidents", _from_lake, _from_oltp)


@incidents.command("events")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--severity", default=None, help="Filter by severity")
@click.option("--limit", default=20, type=int, help="Maximum rows to display")
def incidents_events(path: str | None, severity: str | None, limit: int) -> None:
    """List security events (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "security_events" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            if severity:
                result = engine.query(
                    f"SELECT * FROM read_parquet('{glob}', union_by_name=true) "
                    f"WHERE severity = ? LIMIT ?",
                    [severity, limit],
                )
            else:
                result = engine.query(
                    f"SELECT * FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
                    [limit],
                )
            table = Table(title="Security Events (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import RawEvent
        from warlock.utils import ensure_aware

        init_db()
        with get_read_session() as session:
            q = session.query(RawEvent).filter(RawEvent.source_type.in_(["edr", "siem", "cloud"]))
            rows = q.order_by(RawEvent.ingested_at.desc()).limit(limit).all()

        if not rows:
            console.print("[dim]No security events found.[/dim]")
            return
        table = Table(title="Security Events (OLTP -- from raw events)")
        table.add_column("ID", style="dim")
        table.add_column("Source", style="cyan")
        table.add_column("Type")
        table.add_column("Provider")
        table.add_column("Ingested")
        for r in rows:
            ts = ensure_aware(r.ingested_at).strftime("%Y-%m-%d %H:%M") if r.ingested_at else ""
            table.add_row(
                r.id[:8],
                escape(r.source),
                escape(r.event_type),
                escape(r.provider),
                ts,
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/security_events", _from_lake, _from_oltp)


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
    """List DSAR requests (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "dsars" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
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
            table = Table(title="DSAR Requests (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import Finding

        init_db()
        with get_read_session() as session:
            # DSARs are tracked as findings from privacy connectors
            rows = (
                session.query(Finding)
                .filter(Finding.source_type == "privacy")
                .order_by(Finding.ingested_at.desc())
                .limit(20)
                .all()
            )
            # Also check data_silos for privacy-related data
            if not rows:
                from warlock.db.models import DataSilo

                silos = session.query(DataSilo).limit(20).all()
                if silos:
                    table = Table(title="Data Subject Access -- Data Silos (OLTP)")
                    table.add_column("ID", style="dim")
                    table.add_column("Name", style="cyan")
                    table.add_column("Type")
                    table.add_column("Classification")
                    for s in silos:
                        table.add_row(
                            s.id[:8],
                            escape(s.name or ""),
                            escape(s.silo_type or ""),
                            escape(s.data_classification or ""),
                        )
                    console.print(table)
                    return

        if not rows:
            console.print("[dim]No DSAR data found. Privacy connectors not yet run.[/dim]")
            return
        table = Table(title="Privacy / DSAR Findings (OLTP)")
        table.add_column("ID", style="dim")
        table.add_column("Title")
        table.add_column("Severity")
        table.add_column("Provider")
        for r in rows:
            table.add_row(
                r.id[:8],
                escape(r.title[:60] if r.title else ""),
                escape(r.severity),
                escape(r.provider),
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/dsars", _from_lake, _from_oltp)


@privacy.command("processing")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def privacy_processing(path: str | None) -> None:
    """List processing activities (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "processing_activities" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
            table = Table(title="Processing Activities (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import DataSilo

        init_db()
        with get_read_session() as session:
            rows = session.query(DataSilo).order_by(DataSilo.name).limit(30).all()

        if not rows:
            console.print("[dim]No processing activities found.[/dim]")
            return
        table = Table(title="Processing Activities (OLTP -- from data silos)")
        table.add_column("ID", style="dim")
        table.add_column("Name", style="cyan")
        table.add_column("Type")
        table.add_column("Classification")
        table.add_column("Owner")
        for r in rows:
            table.add_row(
                r.id[:8],
                escape(r.name or ""),
                escape(r.silo_type or ""),
                escape(r.data_classification or ""),
                escape(r.owner or ""),
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/processing_activities", _from_lake, _from_oltp)


@privacy.command("transfers")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def privacy_transfers(path: str | None) -> None:
    """List cross-border data transfers (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "data_transfers" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
            table = Table(title="Cross-Border Data Transfers (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import DataSilo

        init_db()
        with get_read_session() as session:
            rows = (
                session.query(DataSilo)
                .filter(DataSilo.provider.isnot(None))
                .order_by(DataSilo.name)
                .limit(30)
                .all()
            )

        if not rows:
            console.print("[dim]No data transfer records found.[/dim]")
            return
        table = Table(title="Cross-Border Data Transfers (OLTP -- from data silos)")
        table.add_column("ID", style="dim")
        table.add_column("Name", style="cyan")
        table.add_column("Provider")
        table.add_column("Classification")
        table.add_column("Type")
        for r in rows:
            table.add_row(
                r.id[:8],
                escape(r.name or ""),
                escape(r.provider or ""),
                escape(r.data_classification or ""),
                escape(r.silo_type or ""),
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/data_transfers", _from_lake, _from_oltp)


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
    """List SBOM components (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "sbom_components" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true) LIMIT ?",
                [limit],
            )
            table = Table(title="SBOM Components (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import Finding

        init_db()
        with get_read_session() as session:
            rows = (
                session.query(Finding)
                .filter(Finding.observation_type == "inventory")
                .filter(Finding.source_type.in_(["sbom", "scanner", "sca"]))
                .order_by(Finding.ingested_at.desc())
                .limit(limit)
                .all()
            )
            # Broader fallback: any inventory-type finding from dependency scanners
            if not rows:
                rows = (
                    session.query(Finding)
                    .filter(
                        Finding.provider.in_(
                            [
                                "snyk",
                                "dependabot",
                                "trivy",
                                "grype",
                                "github_dependabot",
                                "npm_audit",
                            ]
                        )
                    )
                    .order_by(Finding.ingested_at.desc())
                    .limit(limit)
                    .all()
                )

        if not rows:
            console.print(
                "[dim]No SBOM data found. "
                "Run dependency scanners or import SBOM (CycloneDX/SPDX).[/dim]"
            )
            return
        table = Table(title="SBOM / Dependency Findings (OLTP)")
        table.add_column("ID", style="dim")
        table.add_column("Title")
        table.add_column("Severity")
        table.add_column("Provider", style="cyan")
        table.add_column("Resource")
        for r in rows:
            table.add_row(
                r.id[:8],
                escape(r.title[:50] if r.title else ""),
                escape(r.severity),
                escape(r.provider),
                escape(r.resource_id[:40] if r.resource_id else ""),
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/sbom_components", _from_lake, _from_oltp)


@supply_chain.command("suppliers")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def supply_chain_suppliers(path: str | None) -> None:
    """List supplier assessments (lake with OLTP fallback)."""
    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "supplier_assessments" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
            table = Table(title="Supplier Assessments (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import Vendor

        init_db()
        with get_read_session() as session:
            rows = session.query(Vendor).order_by(Vendor.name).limit(30).all()

        if not rows:
            console.print("[dim]No supplier/vendor data found.[/dim]")
            return
        table = Table(title="Supplier / Vendor Assessments (OLTP)")
        table.add_column("ID", style="dim")
        table.add_column("Name", style="cyan")
        table.add_column("Tier")
        table.add_column("Risk Score", justify="right")
        for r in rows:
            tier_color = {"critical": "red", "high": "red", "medium": "yellow"}.get(
                (r.tier or "").lower(), "dim"
            )
            score_str = f"{r.risk_score:.1f}" if r.risk_score is not None else "N/A"
            table.add_row(
                r.id[:8],
                escape(r.name or ""),
                f"[{tier_color}]{escape(r.tier or 'unrated')}[/{tier_color}]",
                score_str,
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/supplier_assessments", _from_lake, _from_oltp)


@supply_chain.command("concentration")
@click.option("--path", default=None, help="Lake root path (default: from config)")
def supply_chain_concentration(path: str | None) -> None:
    """Show concentration risk analysis (lake with OLTP fallback)."""
    from collections import Counter

    from rich.markup import escape
    from rich.table import Table

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = path or settings.lake_path

    def _from_lake(lp: str) -> None:
        from warlock.lake.query import LakeQueryEngine

        base = Path(lp)
        glob = _safe_lake_path(str(base / "curated" / "concentration_risk" / "**" / "*.parquet"))
        engine = LakeQueryEngine(lp)
        try:
            result = engine.query(
                f"SELECT * FROM read_parquet('{glob}', union_by_name=true)",
                [],
            )
            table = Table(title="Concentration Risk (Lake)")
            if result:
                for col in result[0].keys():
                    table.add_column(col)
                for row in result:
                    table.add_row(*[str(v) for v in row.values()])
            console.print(table)
        finally:
            engine.close()

    def _from_oltp() -> None:
        from warlock.db.engine import get_read_session, init_db
        from warlock.db.models import ConnectorRun

        init_db()
        with get_read_session() as session:
            rows = session.query(ConnectorRun).all()

        if not rows:
            console.print("[dim]No concentration data found.[/dim]")
            return

        # Analyze concentration by provider
        provider_counts: Counter[str] = Counter()
        provider_events: Counter[str] = Counter()
        for r in rows:
            provider_counts[r.provider] += 1
            provider_events[r.provider] += r.event_count or 0

        total_events = sum(provider_events.values())
        table = Table(title="Provider Concentration Risk (OLTP)")
        table.add_column("Provider", style="cyan")
        table.add_column("Runs", justify="right")
        table.add_column("Events", justify="right")
        table.add_column("Share", justify="right")
        table.add_column("Risk")

        for prov, count in provider_counts.most_common(20):
            events = provider_events[prov]
            share = (events / total_events * 100) if total_events else 0
            risk_color = "red" if share > 40 else "yellow" if share > 20 else "green"
            risk_label = "HIGH" if share > 40 else "MEDIUM" if share > 20 else "LOW"
            table.add_row(
                escape(prov),
                str(count),
                str(events),
                f"{share:.1f}%",
                f"[{risk_color}]{risk_label}[/{risk_color}]",
            )
        console.print(table)

    _lake_or_oltp(lake_path, "curated/concentration_risk", _from_lake, _from_oltp)


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
    """Run all lake maintenance jobs (compact, expire, cleanup) with detailed reporting."""
    try:
        import pyarrow  # noqa: F401
    except ImportError:
        _error(
            "pyarrow is required for lake operations but not installed.\n"
            'Install it with: pip install -e ".[lake]"'
        )

    from rich.table import Table as RichTable

    from warlock.config import get_settings
    from warlock.lake.maintenance import run_all_maintenance

    settings = get_settings()
    lake_path = path or settings.lake_path
    console.print(f"[cyan]Running maintenance on {lake_path}...[/cyan]\n")
    results = run_all_maintenance(lake_path)

    # Detailed reporting per job
    table = RichTable(title="Maintenance Report")
    table.add_column("Job", style="cyan")
    table.add_column("Zone/Target")
    table.add_column("Action")
    table.add_column("Count", justify="right")

    total_actions = 0
    for job, stats in results.items():
        if stats:
            for target, count in stats.items():
                action_label = {
                    "compaction": "files compacted",
                    "expiry": "files expired",
                    "orphan_cleanup": "dirs removed",
                }.get(job, "items processed")
                table.add_row(job, str(target), action_label, str(count))
                total_actions += count
        else:
            table.add_row(job, "--", "nothing to do", "0")

    console.print(table)
    if total_actions:
        console.print(f"\n[green]Maintenance complete: {total_actions} actions taken.[/green]")
    else:
        console.print("\n[dim]Maintenance complete: lake is already clean.[/dim]")


@lake.command("search")
@click.argument("query")
@click.option("--path", default=None, help="Lake root path (default: from config)")
@click.option("--zone", default=None, help="Limit to zone (raw, enrichment, curated)")
def lake_search(query: str, path: str | None, zone: str | None) -> None:
    """Search lake table metadata and Parquet file contents by keyword."""
    from rich.markup import escape as rich_escape
    from rich.table import Table as RichTable

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = Path(path or settings.lake_path)

    if not lake_path.exists():
        console.print(f"[yellow]Lake directory does not exist: {lake_path}[/yellow]")
        return

    zones = [zone] if zone else ["raw", "enrichment", "curated"]
    results: list[tuple[str, str, int, int]] = []  # (zone, table_path, files, size)

    query_lower = query.lower()

    for z in zones:
        zone_dir = lake_path / z
        if not zone_dir.exists():
            continue

        # Walk directory structure looking for matching paths
        for dirpath, _dirnames, filenames in __import__("os").walk(str(zone_dir)):
            p = Path(dirpath)
            rel = str(p.relative_to(lake_path))
            parquet_files = [f for f in filenames if f.endswith(".parquet")]

            if not parquet_files:
                continue

            # Match against path components
            if query_lower in rel.lower():
                size = sum((p / f).stat().st_size for f in parquet_files)
                results.append((z, rel, len(parquet_files), size))

    if not results:
        # Try content search via DuckDB if available
        try:
            from warlock.lake.query import LakeQueryEngine

            engine = LakeQueryEngine(str(lake_path))
            try:
                # Search across all zones for the keyword
                for z in zones:
                    zone_dir = lake_path / z
                    if not zone_dir.exists():
                        continue
                    glob_pattern = str(zone_dir / "**" / "*.parquet")
                    if not list(zone_dir.rglob("*.parquet")):
                        continue
                    try:
                        # Get column names from first file
                        cols = engine.query(
                            f"SELECT column_name FROM (DESCRIBE SELECT * FROM "
                            f"read_parquet('{glob_pattern}', union_by_name=true)) LIMIT 50"
                        )
                        col_names = [c["column_name"] for c in cols]
                        # Search text columns for the keyword
                        text_cols = [
                            c
                            for c in col_names
                            if c
                            in (
                                "title",
                                "source",
                                "provider",
                                "framework",
                                "control_id",
                                "connector_name",
                                "event_type",
                                "severity",
                                "status",
                                "observation_type",
                            )
                        ]
                        if text_cols:
                            like_clauses = " OR ".join(
                                f"LOWER(CAST({c} AS VARCHAR)) LIKE ?" for c in text_cols
                            )
                            params = [f"%{query_lower}%"] * len(text_cols)
                            count_result = engine.query(
                                f"SELECT COUNT(*) as cnt FROM "
                                f"read_parquet('{glob_pattern}', union_by_name=true) "
                                f"WHERE {like_clauses}",
                                params,
                            )
                            cnt = count_result[0]["cnt"] if count_result else 0
                            if cnt > 0:
                                console.print(
                                    f"  [cyan]{z}:[/cyan] {cnt} rows match "
                                    f"'{rich_escape(query)}' "
                                    f"(columns: {', '.join(text_cols)})"
                                )
                    except Exception:
                        pass
            finally:
                engine.close()
        except ImportError:
            pass

        if not results:
            console.print(f"[dim]No lake tables or content matching '{rich_escape(query)}'.[/dim]")
        return

    table = RichTable(title=f"Lake Search Results for '{rich_escape(query)}'")
    table.add_column("Zone", style="cyan")
    table.add_column("Path")
    table.add_column("Files", justify="right")
    table.add_column("Size", justify="right")

    for z, rel_path, file_count, size in sorted(results):
        table.add_row(z, rel_path, str(file_count), _format_size(size))

    console.print(table)


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
