"""Data lake analytics CLI commands.

Provides SQL query, summary, source inspection, quality metrics, lineage
tracing, anomaly detection, and trend analysis over the GRC data lake.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

import click
from rich.markup import escape
from rich.table import Table

from warlock.cli import cli, console, _error
from warlock.utils import ensure_aware


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@cli.group("lake-analytics", invoke_without_command=True)
@click.pass_context
def lake_analytics(ctx: click.Context) -> None:
    """Analytical queries and insights over the GRC data lake."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Nested groups
# ---------------------------------------------------------------------------


@lake_analytics.group("anomaly", invoke_without_command=True)
@click.pass_context
def anomaly(ctx: click.Context) -> None:
    """Anomaly detection in finding and event patterns."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@lake_analytics.group("trends", invoke_without_command=True)
@click.pass_context
def trends(ctx: click.Context) -> None:
    """Time-series trend analysis across findings, controls, and connectors."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_lake_engine():
    """Return a LakeQueryEngine pointed at the configured lake path."""
    from warlock.config import get_settings
    from warlock.lake.query import LakeQueryEngine

    settings = get_settings()
    return LakeQueryEngine(lake_path=settings.lake_path)


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} PB"


def _severity_style(severity: str) -> str:
    return {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim",
    }.get(severity.lower(), "")


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


@lake_analytics.command("query")
@click.option("--sql", required=True, help="SQL statement to run against the lake (DuckDB)")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    show_default=True,
    help="Output format",
)
def lake_query(sql: str, fmt: str) -> None:
    """Execute a SQL query directly against the data lake (DuckDB)."""
    try:
        engine = _get_lake_engine()
        rows: list[dict[str, Any]] = engine.query(sql)
        engine.close()
    except Exception as exc:
        _error(f"Query failed: {exc}")

    if not rows:
        console.print("[dim]No rows returned.[/dim]")
        return

    if fmt == "json":
        console.print_json(json.dumps(rows, default=str))
        return

    if fmt == "csv":
        keys = list(rows[0].keys())
        console.print(",".join(keys))
        for row in rows:
            console.print(",".join(str(row.get(k, "")) for k in keys))
        return

    # table
    table = Table(title=f"Query Results ({len(rows)} rows)")
    for col in rows[0].keys():
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*[str(v) if v is not None else "" for v in row.values()])
    console.print(table)


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


@lake_analytics.command("summary")
def lake_summary() -> None:
    """Overview of lake contents: row counts, date ranges, sources, freshness."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, Finding, RawEvent

    init_db()
    with get_session() as session:
        raw_count = session.query(RawEvent).count()
        finding_count = session.query(Finding).count()
        connector_count = session.query(ConnectorRun).count()

        latest_raw = (
            session.query(RawEvent.ingested_at).order_by(RawEvent.ingested_at.desc()).first()
        )
        earliest_raw = (
            session.query(RawEvent.ingested_at).order_by(RawEvent.ingested_at.asc()).first()
        )
        latest_finding = (
            session.query(Finding.ingested_at).order_by(Finding.ingested_at.desc()).first()
        )

        sources = session.query(RawEvent.source, RawEvent.provider).distinct().all()

    table = Table(title="Data Lake Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Raw events", f"{raw_count:,}")
    table.add_row("Findings", f"{finding_count:,}")
    table.add_row("Connector runs", f"{connector_count:,}")
    table.add_row("Unique sources", str(len({s[0] for s in sources})))
    table.add_row(
        "Earliest raw event",
        str(earliest_raw[0])[:19] if earliest_raw and earliest_raw[0] else "—",
    )
    table.add_row(
        "Latest raw event",
        str(latest_raw[0])[:19] if latest_raw and latest_raw[0] else "—",
    )
    table.add_row(
        "Latest finding",
        str(latest_finding[0])[:19] if latest_finding and latest_finding[0] else "—",
    )

    now = _utcnow()
    if latest_raw and latest_raw[0]:
        delta = now - ensure_aware(latest_raw[0])
        hours_ago = delta.total_seconds() / 3600
        freshness = f"{hours_ago:.1f}h ago"
    else:
        freshness = "—"
    table.add_row("Data freshness", freshness)

    console.print(table)


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------


@lake_analytics.command("sources")
def lake_sources() -> None:
    """List all data sources in the lake with row counts and last-updated timestamps."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                RawEvent.source,
                RawEvent.provider,
                RawEvent.source_type,
                func.count(RawEvent.id).label("event_count"),
                func.max(RawEvent.ingested_at).label("last_updated"),
            )
            .group_by(RawEvent.source, RawEvent.provider, RawEvent.source_type)
            .order_by(RawEvent.source, RawEvent.provider)
            .all()
        )

    if not rows:
        console.print("[yellow]No sources found in the lake.[/yellow]")
        return

    table = Table(title=f"Data Sources ({len(rows)} sources)")
    table.add_column("Source", style="cyan")
    table.add_column("Provider")
    table.add_column("Type")
    table.add_column("Events", justify="right")
    table.add_column("Last Updated")

    now = _utcnow()
    for row in rows:
        last = ensure_aware(row.last_updated)
        if last:
            delta = now - last
            age = f"{delta.total_seconds() / 3600:.1f}h ago"
        else:
            age = "—"
        table.add_row(
            row.source,
            row.provider,
            row.source_type,
            f"{row.event_count:,}",
            age,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# freshness
# ---------------------------------------------------------------------------


@lake_analytics.command("freshness")
@click.option("--source", default=None, help="Filter by source name")
@click.option(
    "--threshold-hours",
    "threshold_hours",
    type=int,
    default=24,
    show_default=True,
    help="Flag sources with no data within N hours as stale",
)
def lake_freshness(source: str | None, threshold_hours: int) -> None:
    """Show data freshness per source, flagging stale sources."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        q = session.query(
            RawEvent.source,
            RawEvent.provider,
            func.max(RawEvent.ingested_at).label("last_updated"),
            func.count(RawEvent.id).label("event_count"),
        )
        if source:
            q = q.filter(RawEvent.source == source)
        rows = q.group_by(RawEvent.source, RawEvent.provider).order_by(RawEvent.source).all()

    if not rows:
        console.print("[yellow]No sources found.[/yellow]")
        return

    now = _utcnow()
    threshold = timedelta(hours=threshold_hours)

    table = Table(title=f"Data Freshness (threshold: {threshold_hours}h)")
    table.add_column("Source", style="cyan")
    table.add_column("Provider")
    table.add_column("Last Seen")
    table.add_column("Age", justify="right")
    table.add_column("Status")
    table.add_column("Events", justify="right")

    for row in rows:
        last = ensure_aware(row.last_updated)
        if last:
            delta = now - last
            hours = delta.total_seconds() / 3600
            age_str = f"{hours:.1f}h"
            status = "[red]STALE[/red]" if delta > threshold else "[green]OK[/green]"
        else:
            age_str = "never"
            status = "[red]STALE[/red]"

        table.add_row(
            row.source,
            row.provider,
            str(last)[:19] if last else "—",
            age_str,
            status,
            f"{row.event_count:,}",
        )
    console.print(table)


# ---------------------------------------------------------------------------
# volume
# ---------------------------------------------------------------------------


@lake_analytics.command("volume")
@click.option("--days", type=int, default=7, show_default=True, help="Lookback window in days")
@click.option(
    "--by",
    "group_by",
    type=click.Choice(["source", "event_type", "framework"]),
    default="source",
    show_default=True,
    help="Dimension to group by",
)
def lake_volume(days: int, group_by: str) -> None:
    """Show data volume trends grouped by a chosen dimension."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent
    from sqlalchemy import func

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        if group_by == "event_type":
            col = RawEvent.event_type
        else:
            col = RawEvent.source

        rows = (
            session.query(col, func.count(RawEvent.id).label("count"))
            .filter(RawEvent.ingested_at >= since)
            .group_by(col)
            .order_by(func.count(RawEvent.id).desc())
            .all()
        )

    if not rows:
        console.print(f"[yellow]No data in the past {days} days.[/yellow]")
        return

    total = sum(r.count for r in rows)
    table = Table(title=f"Data Volume — Last {days} Days (by {group_by})")
    table.add_column(group_by.replace("_", " ").title(), style="cyan")
    table.add_column("Events", justify="right")
    table.add_column("Share %", justify="right")

    for row in rows:
        pct = row.count / total * 100 if total else 0
        table.add_row(str(row[0]), f"{row.count:,}", f"{pct:.1f}%")

    console.print(table)
    console.print(f"[dim]Total: {total:,} events[/dim]")


# ---------------------------------------------------------------------------
# quality
# ---------------------------------------------------------------------------


@lake_analytics.command("quality")
@click.option("--source", default=None, help="Filter by source name")
def lake_quality(source: str | None) -> None:
    """Report data quality metrics: nulls, duplicates, and schema violations."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, RawEvent
    from sqlalchemy import func

    init_db()
    with get_session() as session:
        q_findings = session.query(Finding)
        q_raw = session.query(RawEvent)
        if source:
            q_findings = q_findings.filter(Finding.source == source)
            q_raw = q_raw.filter(RawEvent.source == source)

        total_findings = q_findings.count()
        null_resource = q_findings.filter(Finding.resource_id.is_(None)).count()
        null_title = q_findings.filter(Finding.title.is_(None)).count()
        # Duplicate detection: same sha256 appears more than once
        dup_subq = (
            session.query(Finding.sha256, func.count(Finding.id).label("cnt"))
            .group_by(Finding.sha256)
            .having(func.count(Finding.id) > 1)
            .subquery()
        )
        duplicate_hashes = session.query(func.count()).select_from(dup_subq).scalar() or 0

        total_raw = q_raw.count()
        raw_dup_subq = (
            session.query(RawEvent.sha256, func.count(RawEvent.id).label("cnt"))
            .group_by(RawEvent.sha256)
            .having(func.count(RawEvent.id) > 1)
            .subquery()
        )
        raw_dup_count = session.query(func.count()).select_from(raw_dup_subq).scalar() or 0

    table = Table(title=f"Data Quality Metrics{' — ' + source if source else ''}")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Rate", justify="right")

    def pct(n: int, total: int) -> str:
        return f"{n / total * 100:.2f}%" if total else "—"

    table.add_row("Total findings", f"{total_findings:,}", "")
    table.add_row("  Null resource_id", f"{null_resource:,}", pct(null_resource, total_findings))
    table.add_row("  Null title", f"{null_title:,}", pct(null_title, total_findings))
    table.add_row("  Duplicate SHA256 groups", f"{duplicate_hashes:,}", "")
    table.add_row("Total raw events", f"{total_raw:,}", "")
    table.add_row("  Duplicate raw SHA256 groups", f"{raw_dup_count:,}", "")

    console.print(table)


# ---------------------------------------------------------------------------
# lineage
# ---------------------------------------------------------------------------


@lake_analytics.command("lineage")
@click.argument("finding_id")
def lake_lineage(finding_id: str) -> None:
    """Trace a finding back through raw events to the originating connector."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, Finding, RawEvent

    init_db()
    with get_session() as session:
        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            _error(f"Finding not found: {finding_id}")

        raw_event = session.query(RawEvent).filter(RawEvent.id == finding.raw_event_id).first()
        connector_run = None
        if raw_event:
            connector_run = (
                session.query(ConnectorRun)
                .filter(ConnectorRun.id == raw_event.connector_run_id)
                .first()
            )

        console.print(f"\n[bold cyan]Lineage for finding:[/bold cyan] {finding_id}\n")

        # Finding layer
        t_finding = Table(title="Finding", show_header=False)
        t_finding.add_column("Field", style="dim")
        t_finding.add_column("Value")
        t_finding.add_row("ID", finding.id)
        t_finding.add_row("Title", escape(finding.title or "—"))
        t_finding.add_row("Severity", finding.severity)
        t_finding.add_row("Source", f"{finding.source} / {finding.provider}")
        t_finding.add_row(
            "Observed at", str(finding.observed_at)[:19] if finding.observed_at else "—"
        )
        t_finding.add_row("SHA256", finding.sha256[:16] + "...")
        console.print(t_finding)

        if raw_event:
            t_raw = Table(title="Raw Event", show_header=False)
            t_raw.add_column("Field", style="dim")
            t_raw.add_column("Value")
            t_raw.add_row("ID", raw_event.id)
            t_raw.add_row("Event type", raw_event.event_type)
            t_raw.add_row(
                "Ingested at", str(raw_event.ingested_at)[:19] if raw_event.ingested_at else "—"
            )
            t_raw.add_row("SHA256", raw_event.sha256[:16] + "...")
            console.print(t_raw)

        if connector_run:
            t_conn = Table(title="Connector Run", show_header=False)
            t_conn.add_column("Field", style="dim")
            t_conn.add_column("Value")
            t_conn.add_row("ID", connector_run.id)
            t_conn.add_row("Connector", connector_run.connector_name)
            t_conn.add_row("Source", f"{connector_run.source} / {connector_run.provider}")
            t_conn.add_row("Status", connector_run.status)
            t_conn.add_row(
                "Started at",
                str(connector_run.started_at)[:19] if connector_run.started_at else "—",
            )
            t_conn.add_row("Events collected", str(connector_run.event_count))
            console.print(t_conn)

        if not raw_event:
            console.print("[yellow]Warning: raw event not found — lineage is incomplete.[/yellow]")


# ---------------------------------------------------------------------------
# compare-runs
# ---------------------------------------------------------------------------


@lake_analytics.command("compare-runs")
@click.argument("run_id_1")
@click.argument("run_id_2")
def lake_compare_runs(run_id_1: str, run_id_2: str) -> None:
    """Delta analysis between two pipeline connector runs."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        run1 = session.query(ConnectorRun).filter(ConnectorRun.id == run_id_1).first()
        run2 = session.query(ConnectorRun).filter(ConnectorRun.id == run_id_2).first()

        if not run1:
            _error(f"Run not found: {run_id_1}")
        if not run2:
            _error(f"Run not found: {run_id_2}")

        table = Table(title=f"Run Delta: {run_id_1[:8]} vs {run_id_2[:8]}")
        table.add_column("Metric", style="cyan")
        table.add_column(f"Run 1 ({run_id_1[:8]})", justify="right")
        table.add_column(f"Run 2 ({run_id_2[:8]})", justify="right")
        table.add_column("Delta", justify="right")

        def delta_str(a: Any, b: Any) -> str:
            try:
                diff = int(b) - int(a)
                color = "green" if diff >= 0 else "red"
                sign = "+" if diff > 0 else ""
                return f"[{color}]{sign}{diff}[/{color}]"
            except (TypeError, ValueError):
                return "—"

        table.add_row("Connector", run1.connector_name, run2.connector_name, "")
        table.add_row("Status", run1.status, run2.status, "")
        table.add_row(
            "Events collected",
            f"{run1.event_count or 0:,}",
            f"{run2.event_count or 0:,}",
            delta_str(run1.event_count or 0, run2.event_count or 0),
        )
        table.add_row(
            "Errors",
            f"{run1.error_count or 0:,}",
            f"{run2.error_count or 0:,}",
            delta_str(run1.error_count or 0, run2.error_count or 0),
        )
        dur1 = f"{run1.duration_seconds:.1f}s" if run1.duration_seconds else "—"
        dur2 = f"{run2.duration_seconds:.1f}s" if run2.duration_seconds else "—"
        table.add_row("Duration", dur1, dur2, "")
        table.add_row(
            "Started at",
            str(run1.started_at)[:19] if run1.started_at else "—",
            str(run2.started_at)[:19] if run2.started_at else "—",
            "",
        )
        console.print(table)


# ---------------------------------------------------------------------------
# export-parquet
# ---------------------------------------------------------------------------


@lake_analytics.command("export-parquet")
@click.option("--source", default=None, help="Filter by source name")
@click.option("--since", default=None, help="ISO datetime lower bound (e.g. 2026-01-01)")
@click.option(
    "--output",
    "output_dir",
    default="./export",
    show_default=True,
    help="Output directory for Parquet files",
)
def lake_export_parquet(source: str | None, since: str | None, output_dir: str) -> None:
    """Export lake data to Parquet files."""
    import pathlib

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, RawEvent

    init_db()
    out = pathlib.Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    since_dt: datetime | None = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        except ValueError:
            _error(f"Invalid --since date: {since!r}. Use ISO format, e.g. 2026-01-01")

    with get_session() as session:
        q_raw = session.query(RawEvent)
        q_findings = session.query(Finding)
        if source:
            q_raw = q_raw.filter(RawEvent.source == source)
            q_findings = q_findings.filter(Finding.source == source)
        if since_dt:
            q_raw = q_raw.filter(RawEvent.ingested_at >= since_dt)
            q_findings = q_findings.filter(Finding.ingested_at >= since_dt)

        raw_rows = q_raw.all()
        finding_rows = q_findings.all()

    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        _error("pyarrow is required for Parquet export. Install with: pip install pyarrow")

    # Export raw events
    if raw_rows:
        raw_data = [
            {
                "id": r.id,
                "source": r.source,
                "provider": r.provider,
                "source_type": r.source_type,
                "event_type": r.event_type,
                "sha256": r.sha256,
                "ingested_at": str(r.ingested_at),
            }
            for r in raw_rows
        ]
        raw_table = pa.Table.from_pylist(raw_data)
        raw_path = out / "raw_events.parquet"
        pq.write_table(raw_table, str(raw_path))
        console.print(f"[green]Exported {len(raw_rows):,} raw events -> {raw_path}[/green]")

    # Export findings
    if finding_rows:
        finding_data = [
            {
                "id": f.id,
                "observation_type": f.observation_type,
                "title": f.title,
                "source": f.source,
                "provider": f.provider,
                "severity": f.severity,
                "resource_id": f.resource_id or "",
                "resource_type": f.resource_type or "",
                "sha256": f.sha256,
                "observed_at": str(f.observed_at),
                "ingested_at": str(f.ingested_at),
            }
            for f in finding_rows
        ]
        finding_table = pa.Table.from_pylist(finding_data)
        findings_path = out / "findings.parquet"
        pq.write_table(finding_table, str(findings_path))
        console.print(f"[green]Exported {len(finding_rows):,} findings -> {findings_path}[/green]")

    if not raw_rows and not finding_rows:
        console.print("[yellow]No data matched the filter criteria.[/yellow]")


# ---------------------------------------------------------------------------
# partitions
# ---------------------------------------------------------------------------


@lake_analytics.command("partitions")
def lake_partitions() -> None:
    """Show partition layout and sizes in the lake directory."""
    import pathlib

    from warlock.config import get_settings

    settings = get_settings()
    lake_path = pathlib.Path(settings.lake_path)

    if not lake_path.exists():
        console.print(f"[yellow]Lake directory does not exist: {lake_path}[/yellow]")
        console.print("[dim]Run 'warlock lake init' to create it.[/dim]")
        return

    table = Table(title=f"Lake Partitions: {lake_path}")
    table.add_column("Partition", style="cyan")
    table.add_column("Files", justify="right")
    table.add_column("Total Size", justify="right")
    table.add_column("Avg File Size", justify="right")

    total_files = 0
    total_bytes = 0

    for zone_dir in sorted(lake_path.rglob("*")):
        if not zone_dir.is_dir():
            continue
        parquet_files = list(zone_dir.glob("*.parquet"))
        if not parquet_files:
            continue
        zone_bytes = sum(f.stat().st_size for f in parquet_files)
        avg = zone_bytes // len(parquet_files) if parquet_files else 0
        rel = zone_dir.relative_to(lake_path)
        table.add_row(
            str(rel),
            str(len(parquet_files)),
            _format_bytes(zone_bytes),
            _format_bytes(avg),
        )
        total_files += len(parquet_files)
        total_bytes += zone_bytes

    table.add_section()
    table.add_row("[bold]TOTAL[/bold]", str(total_files), _format_bytes(total_bytes), "")
    console.print(table)


# ---------------------------------------------------------------------------
# compact
# ---------------------------------------------------------------------------


@lake_analytics.command("compact")
@click.option("--dry-run", is_flag=True, help="Show what would be compacted without writing")
def lake_compact(dry_run: bool) -> None:
    """Compact small Parquet files in the lake to reduce file-count overhead."""
    import pathlib

    from warlock.config import get_settings

    SMALL_THRESHOLD = 10 * 1024 * 1024  # 10 MB

    settings = get_settings()
    lake_path = pathlib.Path(settings.lake_path)

    if not lake_path.exists():
        console.print("[yellow]Lake directory does not exist.[/yellow]")
        return

    compacted = 0
    for zone_dir in sorted(lake_path.rglob("*")):
        if not zone_dir.is_dir():
            continue
        small_files = [f for f in zone_dir.glob("*.parquet") if f.stat().st_size < SMALL_THRESHOLD]
        if len(small_files) < 2:
            continue

        total_size = sum(f.stat().st_size for f in small_files)
        rel = zone_dir.relative_to(lake_path)
        console.print(
            f"[cyan]{rel}[/cyan]: {len(small_files)} small files "
            f"({_format_bytes(total_size)}) eligible for compaction"
        )

        if not dry_run:
            try:
                import pyarrow.parquet as pq
                import pyarrow as pa

                tables = [pq.read_table(str(f)) for f in small_files]
                merged = pa.concat_tables(tables)
                out_path = zone_dir / "compacted.parquet"
                pq.write_table(merged, str(out_path))
                for f in small_files:
                    f.unlink()
                console.print(f"  [green]Compacted -> {out_path.name}[/green]")
                compacted += 1
            except Exception as exc:
                console.print(f"  [red]Compaction failed: {exc}[/red]")

    if dry_run:
        console.print("[dim](dry-run: no files were modified)[/dim]")
    else:
        console.print(f"\n[green]Compacted {compacted} partition(s).[/green]")


# ---------------------------------------------------------------------------
# retention
# ---------------------------------------------------------------------------


@lake_analytics.command("retention")
def lake_retention() -> None:
    """Show the data retention policy and what data is eligible for purge."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent, Finding
    from warlock.config import get_settings

    settings = get_settings()
    retention_days = getattr(settings, "lake_retention_days", 365)

    init_db()
    cutoff = _utcnow() - timedelta(days=retention_days)

    with get_session() as session:
        raw_total = session.query(RawEvent).count()
        raw_eligible = session.query(RawEvent).filter(RawEvent.ingested_at < cutoff).count()
        finding_total = session.query(Finding).count()
        finding_eligible = session.query(Finding).filter(Finding.ingested_at < cutoff).count()

    table = Table(title="Data Retention Policy")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Retention period", f"{retention_days} days")
    table.add_row("Purge cutoff", str(cutoff)[:19])
    table.add_row("Raw events — total", f"{raw_total:,}")
    table.add_row("Raw events — eligible for purge", f"{raw_eligible:,}")
    table.add_row("Findings — total", f"{finding_total:,}")
    table.add_row("Findings — eligible for purge", f"{finding_eligible:,}")

    console.print(table)
    if raw_eligible > 0 or finding_eligible > 0:
        console.print(
            f"[yellow]Run 'warlock lake-analytics purge --older-than-days {retention_days} --dry-run' to preview.[/yellow]"
        )


# ---------------------------------------------------------------------------
# purge
# ---------------------------------------------------------------------------


@lake_analytics.command("purge")
@click.option(
    "--older-than-days",
    "older_than_days",
    type=int,
    default=365,
    show_default=True,
    help="Purge records older than N days",
)
@click.option("--dry-run", is_flag=True, help="Show what would be purged without deleting")
def lake_purge(older_than_days: int, dry_run: bool) -> None:
    """Purge old data from the lake per the retention policy."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent, Finding

    init_db()
    cutoff = _utcnow() - timedelta(days=older_than_days)

    with get_session() as session:
        raw_q = session.query(RawEvent).filter(RawEvent.ingested_at < cutoff)
        finding_q = session.query(Finding).filter(Finding.ingested_at < cutoff)

        raw_count = raw_q.count()
        finding_count = finding_q.count()

        console.print(f"Cutoff: [yellow]{str(cutoff)[:19]}[/yellow]")
        console.print(f"Raw events eligible: [yellow]{raw_count:,}[/yellow]")
        console.print(f"Findings eligible: [yellow]{finding_count:,}[/yellow]")

        if dry_run:
            console.print("[dim](dry-run: no records deleted)[/dim]")
            return

        if raw_count == 0 and finding_count == 0:
            console.print("[green]Nothing to purge.[/green]")
            return

        click.confirm(
            f"Delete {raw_count + finding_count:,} records older than {older_than_days} days?",
            abort=True,
        )

        raw_q.delete(synchronize_session="fetch")
        finding_q.delete(synchronize_session="fetch")
        session.commit()

    console.print(f"[green]Purged {raw_count:,} raw events and {finding_count:,} findings.[/green]")


# ===========================================================================
# anomaly subgroup
# ===========================================================================


@anomaly.command("detect")
@click.option("--source", default=None, help="Filter by source name")
@click.option("--days", type=int, default=7, show_default=True, help="Analysis window in days")
def anomaly_detect(source: str | None, days: int) -> None:
    """Detect anomalies in finding volume and severity patterns."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding
    from sqlalchemy import func, cast, Date

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        q = session.query(
            cast(Finding.ingested_at, Date).label("day"),
            Finding.severity,
            func.count(Finding.id).label("count"),
        ).filter(Finding.ingested_at >= since)
        if source:
            q = q.filter(Finding.source == source)
        rows = q.group_by("day", Finding.severity).order_by("day").all()

    if not rows:
        console.print("[yellow]No findings in the analysis window.[/yellow]")
        return

    # Compute daily totals and detect spikes (> 2x average)
    daily_totals: dict[str, int] = defaultdict(int)
    for row in rows:
        daily_totals[str(row.day)] += row.count

    if len(daily_totals) < 2:
        console.print("[dim]Not enough days to detect anomalies (need at least 2).[/dim]")
        return

    values = list(daily_totals.values())
    avg = sum(values) / len(values)
    spike_threshold = avg * 2.0
    drop_threshold = avg * 0.3

    anomalies = []
    for day, total in sorted(daily_totals.items()):
        if total > spike_threshold:
            anomalies.append((day, total, "SPIKE", f"{total / avg:.1f}x average"))
        elif total < drop_threshold and avg > 0:
            anomalies.append((day, total, "DROP", f"{total / avg:.1f}x average"))

    console.print(f"[bold]Anomaly Detection[/bold] — {days}-day window, avg {avg:.0f} findings/day")

    if not anomalies:
        console.print("[green]No anomalies detected.[/green]")
        return

    table = Table(title=f"{len(anomalies)} Anomalies Detected")
    table.add_column("Date", style="cyan")
    table.add_column("Findings", justify="right")
    table.add_column("Type")
    table.add_column("Detail")

    for day, total, kind, detail in anomalies:
        color = "red" if kind == "SPIKE" else "yellow"
        table.add_row(day, f"{total:,}", f"[{color}]{kind}[/{color}]", detail)

    console.print(table)


@anomaly.command("list")
@click.option(
    "--severity",
    default=None,
    help="Filter anomalous days by finding severity (critical, high, etc.)",
)
@click.option("--since", default=None, help="ISO datetime lower bound")
def anomaly_list(severity: str | None, since: str | None) -> None:
    """List detected anomalies in the data lake (days with abnormal finding counts)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding
    from sqlalchemy import func, cast, Date

    init_db()
    since_dt = _utcnow() - timedelta(days=30)
    if since:
        try:
            since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        except ValueError:
            _error(f"Invalid --since value: {since!r}")

    with get_session() as session:
        q = session.query(
            cast(Finding.ingested_at, Date).label("day"),
            func.count(Finding.id).label("count"),
        ).filter(Finding.ingested_at >= since_dt)
        if severity:
            q = q.filter(Finding.severity == severity)
        rows = q.group_by("day").order_by("day").all()

    if not rows:
        console.print("[yellow]No findings in the selected window.[/yellow]")
        return

    values = [r.count for r in rows]
    avg = sum(values) / len(values) if values else 0

    table = Table(title="Anomaly List (days > 2x average)")
    table.add_column("Date", style="cyan")
    table.add_column("Findings", justify="right")
    table.add_column("vs Average", justify="right")

    anomaly_count = 0
    for row in rows:
        ratio = row.count / avg if avg else 0
        if ratio > 2.0:
            table.add_row(str(row.day), f"{row.count:,}", f"[red]{ratio:.1f}x[/red]")
            anomaly_count += 1

    if anomaly_count == 0:
        console.print("[green]No anomalous days detected.[/green]")
    else:
        console.print(table)
        console.print(f"[dim]Average: {avg:.0f} findings/day[/dim]")


@anomaly.command("investigate")
@click.argument("anomaly_date")
def anomaly_investigate(anomaly_date: str) -> None:
    """Drill into findings on a specific anomalous date (YYYY-MM-DD)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding
    from sqlalchemy import func

    init_db()
    try:
        target = datetime.strptime(anomaly_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(f"Invalid date: {anomaly_date!r}. Use YYYY-MM-DD format.")

    day_start = target
    day_end = target + timedelta(days=1)

    with get_session() as session:
        total = (
            session.query(Finding)
            .filter(Finding.ingested_at >= day_start, Finding.ingested_at < day_end)
            .count()
        )
        by_severity = (
            session.query(Finding.severity, func.count(Finding.id).label("count"))
            .filter(Finding.ingested_at >= day_start, Finding.ingested_at < day_end)
            .group_by(Finding.severity)
            .order_by(func.count(Finding.id).desc())
            .all()
        )
        by_source = (
            session.query(Finding.source, func.count(Finding.id).label("count"))
            .filter(Finding.ingested_at >= day_start, Finding.ingested_at < day_end)
            .group_by(Finding.source)
            .order_by(func.count(Finding.id).desc())
            .limit(10)
            .all()
        )
        by_type = (
            session.query(Finding.observation_type, func.count(Finding.id).label("count"))
            .filter(Finding.ingested_at >= day_start, Finding.ingested_at < day_end)
            .group_by(Finding.observation_type)
            .order_by(func.count(Finding.id).desc())
            .all()
        )

    console.print(f"\n[bold cyan]Anomaly Investigation: {anomaly_date}[/bold cyan]")
    console.print(f"Total findings: [bold]{total:,}[/bold]\n")

    sev_table = Table(title="By Severity")
    sev_table.add_column("Severity", style="cyan")
    sev_table.add_column("Count", justify="right")
    for row in by_severity:
        style = _severity_style(row.severity)
        sev_table.add_row(f"[{style}]{row.severity}[/{style}]", f"{row.count:,}")
    console.print(sev_table)

    src_table = Table(title="By Source (top 10)")
    src_table.add_column("Source", style="cyan")
    src_table.add_column("Count", justify="right")
    for row in by_source:
        src_table.add_row(row.source, f"{row.count:,}")
    console.print(src_table)

    type_table = Table(title="By Observation Type")
    type_table.add_column("Type", style="cyan")
    type_table.add_column("Count", justify="right")
    for row in by_type:
        type_table.add_row(row.observation_type, f"{row.count:,}")
    console.print(type_table)


# ===========================================================================
# trends subgroup
# ===========================================================================


@trends.command("findings")
@click.option("--days", type=int, default=30, show_default=True, help="Lookback window in days")
@click.option(
    "--by",
    "group_by",
    type=click.Choice(["severity", "source", "type"]),
    default="severity",
    show_default=True,
    help="Dimension to group by",
)
def trends_findings(days: int, group_by: str) -> None:
    """Show finding volume trends over time."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding
    from sqlalchemy import func, cast, Date

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        col_map = {
            "severity": Finding.severity,
            "source": Finding.source,
            "type": Finding.observation_type,
        }
        dim_col = col_map[group_by]

        rows = (
            session.query(
                cast(Finding.ingested_at, Date).label("day"),
                dim_col.label("dimension"),
                func.count(Finding.id).label("count"),
            )
            .filter(Finding.ingested_at >= since)
            .group_by("day", dim_col)
            .order_by("day", func.count(Finding.id).desc())
            .all()
        )

    if not rows:
        console.print(f"[yellow]No findings in the past {days} days.[/yellow]")
        return

    # Aggregate by dimension
    by_dim: dict[str, int] = defaultdict(int)
    for row in rows:
        by_dim[str(row.dimension)] += row.count

    table = Table(title=f"Finding Trends — Last {days} Days (by {group_by})")
    table.add_column(group_by.title(), style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Daily Avg", justify="right")

    for dim, total in sorted(by_dim.items(), key=lambda x: -x[1]):
        table.add_row(dim, f"{total:,}", f"{total / days:.1f}")

    console.print(table)


@trends.command("controls")
@click.option("--days", type=int, default=30, show_default=True, help="Lookback window in days")
@click.option("--framework", default=None, help="Filter by framework")
def trends_controls(days: int, framework: str | None) -> None:
    """Show control pass/fail trends over time."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ControlResult
    from sqlalchemy import func

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id).label("count"),
        ).filter(ControlResult.assessed_at >= since)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        rows = q.group_by(ControlResult.framework, ControlResult.status).all()

    if not rows:
        console.print(f"[yellow]No control results in the past {days} days.[/yellow]")
        return

    # Aggregate by framework
    by_fw: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        by_fw[row.framework][row.status] += row.count

    table = Table(title=f"Control Trends — Last {days} Days")
    table.add_column("Framework", style="cyan")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")
    table.add_column("Not Assessed", justify="right", style="dim")
    table.add_column("Pass Rate", justify="right")

    for fw, statuses in sorted(by_fw.items()):
        compliant = statuses.get("compliant", 0) + statuses.get("inherited_compliant", 0)
        non_compliant = statuses.get("non_compliant", 0)
        partial = statuses.get("partial", 0)
        not_assessed = statuses.get("not_assessed", 0)
        total = sum(statuses.values())
        pass_rate = f"{compliant / total * 100:.1f}%" if total else "—"
        table.add_row(
            fw,
            f"{compliant:,}",
            f"{non_compliant:,}",
            f"{partial:,}",
            f"{not_assessed:,}",
            pass_rate,
        )

    console.print(table)


@trends.command("risk")
@click.option("--days", type=int, default=30, show_default=True, help="Lookback window in days")
def trends_risk(days: int) -> None:
    """Show risk score trends (severity distribution over time)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding
    from sqlalchemy import func, cast, Date

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        rows = (
            session.query(
                cast(Finding.ingested_at, Date).label("day"),
                Finding.severity,
                func.count(Finding.id).label("count"),
            )
            .filter(Finding.ingested_at >= since)
            .group_by("day", Finding.severity)
            .order_by("day")
            .all()
        )

    if not rows:
        console.print(f"[yellow]No findings in the past {days} days.[/yellow]")
        return

    # Compute a simple risk score per day: weight by severity
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    daily_scores: dict[str, float] = defaultdict(float)
    daily_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        w = weights.get(row.severity, 0)
        daily_scores[str(row.day)] += w * row.count
        daily_counts[str(row.day)] += row.count

    table = Table(title=f"Risk Score Trends — Last {days} Days")
    table.add_column("Date", style="cyan")
    table.add_column("Risk Score", justify="right")
    table.add_column("Findings", justify="right")

    for day in sorted(daily_scores):
        score = daily_scores[day]
        color = "red" if score > 500 else "yellow" if score > 100 else "green"
        table.add_row(day, f"[{color}]{score:.0f}[/{color}]", f"{daily_counts[day]:,}")

    console.print(table)
    console.print("[dim]Risk score = weighted sum: critical*10 + high*5 + medium*2 + low*1[/dim]")


@trends.command("connectors")
@click.option("--days", type=int, default=30, show_default=True, help="Lookback window in days")
def trends_connectors(days: int) -> None:
    """Show connector data volume trends over time."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun
    from sqlalchemy import func

    init_db()
    since = _utcnow() - timedelta(days=days)

    with get_session() as session:
        rows = (
            session.query(
                ConnectorRun.connector_name,
                func.count(ConnectorRun.id).label("runs"),
                func.sum(ConnectorRun.event_count).label("total_events"),
                func.sum(ConnectorRun.error_count).label("total_errors"),
                func.avg(ConnectorRun.duration_seconds).label("avg_duration"),
            )
            .filter(ConnectorRun.started_at >= since)
            .group_by(ConnectorRun.connector_name)
            .order_by(func.sum(ConnectorRun.event_count).desc())
            .all()
        )

    if not rows:
        console.print(f"[yellow]No connector runs in the past {days} days.[/yellow]")
        return

    table = Table(title=f"Connector Trends — Last {days} Days")
    table.add_column("Connector", style="cyan")
    table.add_column("Runs", justify="right")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Avg Duration", justify="right")

    for row in rows:
        err_style = "red" if (row.total_errors or 0) > 0 else "green"
        dur = f"{row.avg_duration:.1f}s" if row.avg_duration else "—"
        table.add_row(
            row.connector_name,
            f"{row.runs:,}",
            f"{row.total_events or 0:,}",
            f"[{err_style}]{row.total_errors or 0:,}[/{err_style}]",
            dur,
        )

    console.print(table)


# ===========================================================================
# DLA-1: Saved Queries
# ===========================================================================


_BUILTIN_TEMPLATES: dict[str, dict[str, str]] = {
    "sla_breach": {
        "name": "SLA Breach Detection",
        "description": "Find POAMs past their scheduled completion date",
        "sql": (
            "SELECT id, framework, control_id, severity, status, "
            "scheduled_completion, weakness_description "
            "FROM poams "
            "WHERE status NOT IN ('closed', 'verified') "
            "AND scheduled_completion < CURRENT_TIMESTAMP "
            "ORDER BY scheduled_completion ASC"
        ),
    },
    "control_drift_30d": {
        "name": "Control Drift (30 days)",
        "description": "Controls that changed status in the last 30 days",
        "sql": (
            "SELECT framework, control_id, status, severity, assessed_at "
            "FROM control_results "
            "WHERE assessed_at >= datetime('now', '-30 days') "
            "AND status IN ('non_compliant', 'partial') "
            "ORDER BY assessed_at DESC"
        ),
    },
    "top_failures": {
        "name": "Top Failure Controls",
        "description": "Controls with the most non-compliant findings",
        "sql": (
            "SELECT framework, control_id, COUNT(*) as failure_count "
            "FROM control_results "
            "WHERE status = 'non_compliant' "
            "GROUP BY framework, control_id "
            "ORDER BY failure_count DESC "
            "LIMIT 25"
        ),
    },
    "remediation_velocity": {
        "name": "Remediation Velocity",
        "description": "Average time from POAM creation to completion by framework",
        "sql": (
            "SELECT framework, "
            "COUNT(*) as completed, "
            "AVG(JULIANDAY(actual_completion) - JULIANDAY(created_at)) as avg_days "
            "FROM poams "
            "WHERE status IN ('completed', 'verified', 'closed') "
            "AND actual_completion IS NOT NULL "
            "GROUP BY framework "
            "ORDER BY avg_days ASC"
        ),
    },
}


@lake_analytics.command("save-query")
@click.option("--name", required=True, help="Unique name for the saved query")
@click.option("--sql", "sql_text", required=True, help="SQL statement to save")
@click.option("--description", default="", help="Description of the query")
@click.option("--shared", is_flag=True, help="Make this query visible to all users")
def lake_save_query(name: str, sql_text: str, description: str, shared: bool) -> None:
    """Save a reusable SQL query for later execution."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SavedQuery

    init_db()
    with get_session() as session:
        existing = session.query(SavedQuery).filter(SavedQuery.name == name).first()
        if existing:
            _error(
                f"Query with name '{name}' already exists. Delete it first or use a different name."
            )

        sq = SavedQuery(
            name=name,
            sql_text=sql_text,
            description=description,
            query_type="custom",
            shared=shared,
        )
        session.add(sq)
        session.commit()

    console.print(f"[green]Saved query '{escape(name)}'.[/green]")


@lake_analytics.command("list-queries")
def lake_list_queries() -> None:
    """List all saved queries with metadata."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SavedQuery

    init_db()
    with get_session() as session:
        queries = session.query(SavedQuery).order_by(SavedQuery.name).all()

    if not queries:
        console.print(
            "[yellow]No saved queries. Use 'lake-analytics save-query' to create one.[/yellow]"
        )
        return

    table = Table(title=f"Saved Queries ({len(queries)})")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Description")
    table.add_column("Shared")
    table.add_column("Last Run")
    table.add_column("Runs", justify="right")

    for sq in queries:
        last_run = _iso_str(sq.last_run_at) if sq.last_run_at else "never"
        table.add_row(
            escape(sq.name),
            sq.query_type or "custom",
            escape(sq.description or ""),
            "yes" if sq.shared else "no",
            last_run,
            str(sq.run_count or 0),
        )

    console.print(table)


@lake_analytics.command("run-query")
@click.argument("name")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    show_default=True,
    help="Output format",
)
def lake_run_query(name: str, fmt: str) -> None:
    """Execute a saved query by name and display results."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SavedQuery

    init_db()
    with get_session() as session:
        sq = session.query(SavedQuery).filter(SavedQuery.name == name).first()
        if not sq:
            _error(
                f"Saved query '{name}' not found. Use 'lake-analytics list-queries' to see available queries."
            )

        sql = sq.sql_text

        # Update run metadata
        sq.run_count = (sq.run_count or 0) + 1
        sq.last_run_at = _utcnow()
        session.commit()

    # Execute the query against the database
    from warlock.db.engine import get_session as gs

    with gs() as session:
        try:
            result = session.execute(__import__("sqlalchemy").text(sql))
            rows = [dict(row._mapping) for row in result]
        except Exception as exc:
            _error(f"Query execution failed: {exc}")

    if not rows:
        console.print("[dim]No rows returned.[/dim]")
        return

    if fmt == "json":
        console.print_json(json.dumps(rows, default=str))
        return

    if fmt == "csv":
        keys = list(rows[0].keys())
        console.print(",".join(keys))
        for row in rows:
            console.print(",".join(str(row.get(k, "")) for k in keys))
        return

    table = Table(title=f"Query: {escape(name)} ({len(rows)} rows)")
    for col in rows[0].keys():
        table.add_column(str(col), overflow="fold")
    for row in rows:
        table.add_row(*[str(v) if v is not None else "" for v in row.values()])
    console.print(table)


@lake_analytics.command("delete-query")
@click.argument("name")
def lake_delete_query(name: str) -> None:
    """Delete a saved query by name."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import SavedQuery

    init_db()
    with get_session() as session:
        sq = session.query(SavedQuery).filter(SavedQuery.name == name).first()
        if not sq:
            _error(f"Saved query '{name}' not found.")

        session.delete(sq)
        session.commit()

    console.print(f"[green]Deleted query '{escape(name)}'.[/green]")


@lake_analytics.command("query-templates")
def lake_query_templates() -> None:
    """Show built-in query templates for common GRC analytics patterns."""
    table = Table(title=f"Built-in Query Templates ({len(_BUILTIN_TEMPLATES)})")
    table.add_column("Key", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")

    for key, tmpl in sorted(_BUILTIN_TEMPLATES.items()):
        table.add_row(key, tmpl["name"], tmpl["description"])

    console.print(table)
    console.print(
        "\n[dim]Use a template: "
        "warlock lake-analytics save-query --name my_query "
        '--sql "<paste SQL from template>"[/dim]'
    )

    # Also print the SQL for each template
    for key, tmpl in sorted(_BUILTIN_TEMPLATES.items()):
        console.print(f"\n[bold cyan]{tmpl['name']}[/bold cyan] ({key}):")
        console.print(f"[dim]{tmpl['sql']}[/dim]")


def _iso_str(dt: datetime | None) -> str:
    """Format a datetime for CLI display, handling naive datetimes."""
    if dt is None:
        return ""
    dt = ensure_aware(dt)
    return dt.strftime("%Y-%m-%d %H:%M")


# ===========================================================================
# DLA-3: Time-travel
# ===========================================================================


@lake_analytics.command("time-travel")
@click.option(
    "--date",
    "target_date",
    required=True,
    help="Historical date to query (YYYY-MM-DD)",
)
@click.option("--framework", default=None, help="Filter by framework")
def lake_time_travel(target_date: str, framework: str | None) -> None:
    """Query historical compliance posture from PostureSnapshot at a given date.

    Shows the compliance state as it was on the specified date, using
    the closest PostureSnapshot records on or before that date.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import PostureSnapshot
    from sqlalchemy import func

    init_db()
    try:
        dt = datetime.strptime(target_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(f"Invalid date format: {target_date!r}. Use YYYY-MM-DD.")

    # End of the target day
    dt_end = dt + timedelta(days=1)

    with get_session() as session:
        # Find the latest snapshot for each (framework, control_id) on or before target date
        subq = session.query(
            PostureSnapshot.framework,
            PostureSnapshot.control_id,
            func.max(PostureSnapshot.snapshot_date).label("max_date"),
        ).filter(PostureSnapshot.snapshot_date < dt_end)
        if framework:
            subq = subq.filter(PostureSnapshot.framework == framework)
        subq = subq.group_by(
            PostureSnapshot.framework,
            PostureSnapshot.control_id,
        ).subquery()

        snapshots = (
            session.query(PostureSnapshot)
            .join(
                subq,
                (PostureSnapshot.framework == subq.c.framework)
                & (PostureSnapshot.control_id == subq.c.control_id)
                & (PostureSnapshot.snapshot_date == subq.c.max_date),
            )
            .all()
        )

    if not snapshots:
        console.print(
            f"[yellow]No posture snapshots found on or before {target_date}."
            f"{' Framework: ' + framework if framework else ''}[/yellow]"
        )
        return

    # Aggregate by framework
    by_fw: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for s in snapshots:
        by_fw[s.framework][s.status] += 1

    console.print(f"\n[bold]Compliance Posture as of {target_date}[/bold]\n")

    table = Table(title=f"Historical Posture ({len(snapshots)} controls)")
    table.add_column("Framework", style="cyan")
    table.add_column("Compliant", justify="right", style="green")
    table.add_column("Non-Compliant", justify="right", style="red")
    table.add_column("Partial", justify="right", style="yellow")
    table.add_column("Not Assessed", justify="right", style="dim")
    table.add_column("Total", justify="right")
    table.add_column("Pass Rate", justify="right")

    for fw in sorted(by_fw):
        statuses = by_fw[fw]
        c = statuses.get("compliant", 0)
        nc = statuses.get("non_compliant", 0)
        p = statuses.get("partial", 0)
        na = statuses.get("not_assessed", 0)
        total = c + nc + p + na
        rate = f"{c / total * 100:.1f}%" if total else "N/A"
        table.add_row(fw, str(c), str(nc), str(p), str(na), str(total), rate)

    console.print(table)


# ===========================================================================
# DLA-4: Tiered storage
# ===========================================================================


@lake_analytics.command("storage-tiers")
def lake_storage_tiers() -> None:
    """Show data distribution across hot/warm/cold tiers based on record age.

    Hot: <30 days, Warm: 30-180 days, Cold: >180 days.
    Shows counts and estimated storage per tier.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import Finding, RawEvent

    init_db()
    now = _utcnow()
    hot_cutoff = now - timedelta(days=30)
    warm_cutoff = now - timedelta(days=180)

    with get_session() as session:
        # Raw events by tier
        raw_hot = session.query(RawEvent).filter(RawEvent.ingested_at >= hot_cutoff).count()
        raw_warm = (
            session.query(RawEvent)
            .filter(RawEvent.ingested_at >= warm_cutoff, RawEvent.ingested_at < hot_cutoff)
            .count()
        )
        raw_cold = session.query(RawEvent).filter(RawEvent.ingested_at < warm_cutoff).count()

        # Findings by tier
        find_hot = session.query(Finding).filter(Finding.ingested_at >= hot_cutoff).count()
        find_warm = (
            session.query(Finding)
            .filter(Finding.ingested_at >= warm_cutoff, Finding.ingested_at < hot_cutoff)
            .count()
        )
        find_cold = session.query(Finding).filter(Finding.ingested_at < warm_cutoff).count()

    # Estimate ~1 KB per raw event, ~2 KB per finding (rough sizing)
    est_raw_kb = 1
    est_find_kb = 2

    table = Table(title="Storage Tiers (by record age)")
    table.add_column("Tier", style="bold")
    table.add_column("Age Range")
    table.add_column("Raw Events", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Total Records", justify="right")
    table.add_column("Est. Storage", justify="right")

    def _est_size(raw: int, findings: int) -> str:
        total_kb = raw * est_raw_kb + findings * est_find_kb
        return _format_bytes(total_kb * 1024)

    table.add_row(
        "[green]Hot[/green]",
        "<30 days",
        f"{raw_hot:,}",
        f"{find_hot:,}",
        f"{raw_hot + find_hot:,}",
        _est_size(raw_hot, find_hot),
    )
    table.add_row(
        "[yellow]Warm[/yellow]",
        "30-180 days",
        f"{raw_warm:,}",
        f"{find_warm:,}",
        f"{raw_warm + find_warm:,}",
        _est_size(raw_warm, find_warm),
    )
    table.add_row(
        "[dim]Cold[/dim]",
        ">180 days",
        f"{raw_cold:,}",
        f"{find_cold:,}",
        f"{raw_cold + find_cold:,}",
        _est_size(raw_cold, find_cold),
    )

    table.add_section()
    total_raw = raw_hot + raw_warm + raw_cold
    total_find = find_hot + find_warm + find_cold
    table.add_row(
        "[bold]Total[/bold]",
        "",
        f"{total_raw:,}",
        f"{total_find:,}",
        f"{total_raw + total_find:,}",
        _est_size(total_raw, total_find),
    )

    console.print(table)


# ===========================================================================
# DLA-10: Historical risk
# ===========================================================================


@lake_analytics.command("risk-history")
@click.option("--framework", default=None, help="Filter by framework")
@click.option(
    "--months",
    type=int,
    default=6,
    show_default=True,
    help="Number of months to look back",
)
def lake_risk_history(framework: str | None, months: int) -> None:
    """Show risk analysis trends over time (mean ALE and VaR 95% by month)."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RiskAnalysis
    from sqlalchemy import func, extract

    init_db()
    since = _utcnow() - timedelta(days=months * 30)

    with get_session() as session:
        q = session.query(
            extract("year", RiskAnalysis.created_at).label("year"),
            extract("month", RiskAnalysis.created_at).label("month"),
            func.avg(RiskAnalysis.mean_ale).label("avg_ale"),
            func.avg(RiskAnalysis.var_95).label("avg_var95"),
            func.count(RiskAnalysis.id).label("analyses"),
        ).filter(RiskAnalysis.created_at >= since)

        if framework:
            q = q.filter(RiskAnalysis.framework == framework)

        rows = q.group_by("year", "month").order_by("year", "month").all()

    if not rows:
        console.print(
            f"[yellow]No risk analyses found in the past {months} months."
            f"{' Framework: ' + framework if framework else ''}[/yellow]"
        )
        return

    table = Table(
        title=f"Risk History — Last {months} Months" + (f" ({framework})" if framework else "")
    )
    table.add_column("Month", style="cyan")
    table.add_column("Analyses", justify="right")
    table.add_column("Avg Mean ALE", justify="right")
    table.add_column("Avg VaR 95%", justify="right")
    table.add_column("Trend")

    prev_ale: float | None = None
    for row in rows:
        year = int(row.year)
        month = int(row.month)
        month_str = f"{year}-{month:02d}"
        avg_ale = float(row.avg_ale) if row.avg_ale else 0.0
        avg_var = float(row.avg_var95) if row.avg_var95 else 0.0

        # Trend indicator
        if prev_ale is not None:
            if avg_ale > prev_ale * 1.1:
                trend = "[red]UP[/red]"
            elif avg_ale < prev_ale * 0.9:
                trend = "[green]DOWN[/green]"
            else:
                trend = "[dim]STABLE[/dim]"
        else:
            trend = "—"
        prev_ale = avg_ale

        table.add_row(
            month_str,
            str(row.analyses),
            f"${avg_ale:,.0f}",
            f"${avg_var:,.0f}",
            trend,
        )

    console.print(table)
