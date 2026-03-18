"""CLI — the interface to the pipeline."""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """Warlock — compliance telemetry pipeline."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


@cli.command()
def init() -> None:
    """Initialize the database."""
    from warlock.db.engine import init_db
    init_db()
    console.print("[green]Database initialized.[/green]")


@cli.command()
@click.option("--source", "-s", multiple=True, help="Limit to specific sources (e.g., aws)")
def collect(source: tuple[str, ...]) -> None:
    """Run the full pipeline: collect → normalize → map → assess."""
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.orchestrator import Pipeline
    from warlock.pipeline.bus import EventBus

    # Bootstrap
    init_db()
    bus = EventBus()
    pipeline = _build_pipeline(bus, sources=source or None)

    # Wire up a simple event logger
    bus.subscribe_all(lambda e: logging.getLogger("bus").debug(
        "%s → %s", e.event_type, e.payload_id[:8]
    ))

    # Run
    with get_session() as session:
        stats = pipeline.run(session)

    # Report
    _print_stats(stats)


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
@click.option("--status", default=None, help="Filter by status")
@click.option("--limit", "-n", default=50, help="Max results")
def results(framework: str | None, status: str | None, limit: int) -> None:
    """Query control results from the last pipeline run."""
    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult

    with get_session() as session:
        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        if status:
            q = q.filter(ControlResult.status == status)
        q = q.order_by(ControlResult.assessed_at.desc()).limit(limit)
        rows = q.all()

    if not rows:
        console.print("[dim]No results found.[/dim]")
        return

    table = Table(title=f"Control Results ({len(rows)})")
    table.add_column("Framework", style="cyan")
    table.add_column("Control", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Assessor", style="dim")

    for r in rows:
        status_style = {
            "compliant": "green",
            "non_compliant": "red",
            "partial": "yellow",
            "not_assessed": "dim",
        }.get(r.status, "")
        sev_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "dim",
        }.get(r.severity, "")
        table.add_row(
            r.framework, r.control_id,
            f"[{status_style}]{r.status}[/]",
            f"[{sev_style}]{r.severity}[/]",
            r.assessor,
        )

    console.print(table)


@cli.command()
@click.option("--framework", "-f", default=None, help="Filter by framework")
def coverage(framework: str | None) -> None:
    """Show compliance coverage summary."""
    from sqlalchemy import func
    from warlock.db.engine import get_session
    from warlock.db.models import ControlResult

    with get_session() as session:
        q = session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id),
        ).group_by(ControlResult.framework, ControlResult.status)

        if framework:
            q = q.filter(ControlResult.framework == framework)

        rows = q.all()

    if not rows:
        console.print("[dim]No results found. Run 'warlock collect' first.[/dim]")
        return

    # Aggregate by framework
    data: dict[str, dict[str, int]] = {}
    for fw, status, count in rows:
        data.setdefault(fw, {})
        data[fw][status] = count

    table = Table(title="Compliance Coverage")
    table.add_column("Framework", style="cyan")
    table.add_column("Compliant", style="green")
    table.add_column("Non-Compliant", style="red")
    table.add_column("Partial", style="yellow")
    table.add_column("Not Assessed", style="dim")
    table.add_column("Total")
    table.add_column("Rate")

    for fw, counts in sorted(data.items()):
        total = sum(counts.values())
        compliant = counts.get("compliant", 0)
        rate = (compliant / total * 100) if total else 0
        rate_style = "green" if rate >= 80 else "yellow" if rate >= 50 else "red"
        table.add_row(
            fw,
            str(compliant),
            str(counts.get("non_compliant", 0)),
            str(counts.get("partial", 0)),
            str(counts.get("not_assessed", 0)),
            str(total),
            f"[{rate_style}]{rate:.0f}%[/]",
        )

    console.print(table)


@cli.command()
def findings() -> None:
    """Show recent findings."""
    from warlock.db.engine import get_session
    from warlock.db.models import Finding

    with get_session() as session:
        rows = session.query(Finding).order_by(Finding.ingested_at.desc()).limit(50).all()

    if not rows:
        console.print("[dim]No findings. Run 'warlock collect' first.[/dim]")
        return

    table = Table(title=f"Findings ({len(rows)})")
    table.add_column("Type", style="cyan")
    table.add_column("Title")
    table.add_column("Resource")
    table.add_column("Severity")
    table.add_column("Source", style="dim")

    for f in rows:
        sev_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(f.severity, "dim")
        table.add_row(
            f.observation_type,
            f.title[:80],
            f.resource_type or "",
            f"[{sev_style}]{f.severity}[/]",
            f.provider,
        )

    console.print(table)


@cli.command()
def connectors() -> None:
    """List registered connector types."""
    from warlock.connectors.base import registry as conn_registry
    _load_connectors()
    table = Table(title="Registered Connectors")
    table.add_column("Provider")
    table.add_column("Status")
    for provider in conn_registry.list_types():
        table.add_row(provider, "[green]registered[/green]")
    console.print(table)


# ---------------------------------------------------------------------------
# Pipeline assembly
# ---------------------------------------------------------------------------

def _build_pipeline(bus, sources: tuple[str, ...] | None = None):
    from warlock.connectors.base import ConnectorConfig, ConnectorRegistry, SourceType, registry as type_registry
    from warlock.normalizers.base import NormalizerRegistry, registry as norm_registry
    from warlock.mappers.control_mapper import ControlMapper
    from warlock.assessors.engine import Assessor, engine as assertion_engine
    from warlock.pipeline.orchestrator import Pipeline
    from warlock.config import get_settings

    settings = get_settings()

    # Load connector types
    _load_connectors()

    # Build connector registry with configured sources
    connectors = ConnectorRegistry()
    connectors._types = type_registry._types  # share registered types

    if settings.aws_enabled and (sources is None or "aws" in sources):
        connectors.create(ConnectorConfig(
            name="aws",
            source_type=SourceType.CLOUD,
            provider="aws",
            settings={"regions": settings.aws_regions, "assume_role_arn": settings.aws_assume_role_arn},
        ))

    # Load normalizers
    _load_normalizers()

    # Build mapper (empty for now — loaded from framework configs)
    mapper = ControlMapper()

    # Build assessor
    assessor = Assessor(engine=assertion_engine)

    return Pipeline(
        connectors=connectors,
        normalizers=norm_registry,
        mapper=mapper,
        assessor=assessor,
        bus=bus,
    )


def _load_connectors():
    """Import connector modules to trigger registration."""
    try:
        import warlock.connectors.aws  # noqa: F401
    except ImportError:
        pass


def _load_normalizers():
    """Import normalizer modules to trigger registration."""
    try:
        import warlock.normalizers.aws  # noqa: F401
    except ImportError:
        pass


def _print_stats(stats) -> None:
    table = Table(title="Pipeline Run")
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    table.add_row("Raw events collected", str(stats.raw_events_collected))
    table.add_row("Findings normalized", str(stats.findings_normalized))
    table.add_row("Controls mapped", str(stats.controls_mapped))
    table.add_row("Results assessed", str(stats.results_assessed))
    table.add_row("Connectors OK", str(stats.connectors_succeeded))
    table.add_row("Connectors failed", str(stats.connectors_failed))
    table.add_row("Duration", f"{stats.duration_seconds:.1f}s" if stats.duration_seconds else "—")
    if stats.errors:
        table.add_row("Errors", str(len(stats.errors)))
    console.print(table)

    if stats.errors:
        console.print(f"\n[yellow]Errors ({len(stats.errors)}):[/yellow]")
        for err in stats.errors[:10]:
            console.print(f"  [dim]• {err}[/dim]")
        if len(stats.errors) > 10:
            console.print(f"  [dim]... and {len(stats.errors) - 10} more[/dim]")


if __name__ == "__main__":
    cli()
