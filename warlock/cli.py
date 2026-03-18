"""CLI — the interface to the pipeline."""

from __future__ import annotations

import logging

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
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline

    # Bootstrap
    init_db()
    bus = EventBus()
    pipeline = build_pipeline(bus, sources=source or None)

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
    from warlock.pipeline.loader import load_all_connectors

    load_all_connectors()
    table = Table(title="Registered Connectors")
    table.add_column("Provider")
    table.add_column("Status")
    for provider in conn_registry.list_types():
        table.add_row(provider, "[green]registered[/green]")
    console.print(table)


@cli.command()
def sources() -> None:
    """List all registered connector types and normalizer types."""
    from warlock.connectors.base import registry as conn_registry
    from warlock.normalizers.base import registry as norm_registry
    from warlock.pipeline.loader import load_all_connectors, load_all_normalizers

    load_all_connectors()
    load_all_normalizers()

    table = Table(title="Registered Sources")
    table.add_column("Type", style="cyan")
    table.add_column("Name")
    table.add_column("Status")

    for provider in sorted(conn_registry.list_types()):
        table.add_row("connector", provider, "[green]registered[/green]")
    for normalizer in norm_registry._normalizers:
        name = type(normalizer).__name__
        table.add_row("normalizer", name, "[green]registered[/green]")

    console.print(table)


@cli.command()
@click.option("--source", "-s", required=True, help="Source identifier (e.g., webhook, manual)")
@click.option("--provider", "-p", required=True, help="Provider name (e.g., crowdstrike, okta)")
@click.option("--event-type", "-t", required=True, help="Event type label (e.g., falcon_detections)")
@click.option("--file", "-f", "file_path", required=True, type=click.Path(exists=True), help="Path to JSON file")
def ingest(source: str, provider: str, event_type: str, file_path: str) -> None:
    """Ingest a JSON file through the webhook receiver and pipeline."""
    import json
    from warlock.connectors.webhook import WebhookReceiver
    from warlock.connectors.base import ConnectorResult, SourceType
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline

    # Read the JSON payload
    with open(file_path) as fh:
        payload = json.load(fh)

    # Wrap in a list if it's a single object
    payloads = payload if isinstance(payload, list) else [payload]

    # Bootstrap
    init_db()
    bus = EventBus()
    pipeline = build_pipeline(bus)

    # Ingest through the webhook receiver
    receiver = WebhookReceiver()
    raw_events = receiver.ingest_batch(
        payloads, source=source, provider=provider, event_type=event_type,
    )

    # Synthesise a ConnectorResult so the pipeline persistence works
    cr = ConnectorResult(
        connector_name=f"ingest:{source}",
        source=source,
        source_type=raw_events[0].source_type if raw_events else SourceType.CUSTOM,
        provider=provider,
        events=raw_events,
    )
    cr.complete()

    # Run through stages 2-4 by feeding the connector result into the pipeline
    from warlock.pipeline.orchestrator import PipelineRunStats
    stats = PipelineRunStats()

    with get_session() as session:
        db_run = pipeline._persist_connector_run(session, cr)
        stats.connectors_succeeded = 1

        for raw_event in cr.events:
            db_raw = pipeline._persist_raw_event(session, raw_event, db_run.id)
            stats.raw_events_collected += 1

            findings = pipeline.normalizers.normalize(raw_event)
            for finding in findings:
                finding.raw_event_id = db_raw.id
                db_finding = pipeline._persist_finding(session, finding)
                stats.findings_normalized += 1

                mapped = pipeline.mapper.map(finding)
                for mapping in mapped.mappings:
                    pipeline._persist_mapping(session, mapping)
                    stats.controls_mapped += 1

                results = pipeline.assessor.assess(mapped, raw_data=raw_event.raw_data)
                for result in results:
                    pipeline._persist_result(session, result)
                    stats.results_assessed += 1

        session.flush()

    from datetime import datetime, timezone
    stats.completed_at = datetime.now(timezone.utc)
    _print_stats(stats)


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
