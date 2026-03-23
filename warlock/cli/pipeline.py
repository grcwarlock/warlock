"""Pipeline commands: init, collect, ingest, scheduler."""

from __future__ import annotations

import logging

import click

from warlock.cli import cli, console, _print_stats


@cli.command()
def init() -> None:
    """Initialize the database."""
    from warlock.db.engine import init_db

    init_db()
    console.print("[green]Database initialized.[/green]")


@cli.command()
@click.option("--source", "-s", multiple=True, help="Limit to specific sources (e.g., aws)")
def collect(source: tuple[str, ...]) -> None:
    """Run the full pipeline: collect -> normalize -> map -> assess."""
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline, register_lake_writer

    # Bootstrap
    init_db()
    bus = EventBus()
    lake_writer = register_lake_writer(bus)
    pipeline = build_pipeline(bus, sources=source or None)

    # Wire up a simple event logger
    bus.subscribe_all(
        lambda e: logging.getLogger("bus").debug("%s -> %s", e.event_type, e.payload_id[:8])
    )

    # Run with progress indicator
    with console.status(
        "[bold cyan]Running pipeline (collect → normalize → map → assess)...[/bold cyan]"
    ):
        with get_session() as session:
            stats = pipeline.run(session)

    # Flush lake writer if enabled
    if lake_writer is not None:
        with get_session() as lake_session:
            lake_stats = lake_writer.flush(stats.run_id, lake_session)
            logging.getLogger(__name__).info(
                "Lake write: %d raw, %d findings, %d results",
                lake_stats.raw_events_written,
                lake_stats.findings_written,
                lake_stats.control_results_written,
            )

    # Report
    _print_stats(stats)
    if stats.errors:
        raise SystemExit(1)


@cli.command()
@click.option("--source", "-s", required=True, help="Source identifier (e.g., webhook, manual)")
@click.option("--provider", "-p", required=True, help="Provider name (e.g., crowdstrike, okta)")
@click.option(
    "--event-type", "-t", required=True, help="Event type label (e.g., falcon_detections)"
)
@click.option(
    "--input-file",
    "file_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to JSON file",
)
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
        payloads,
        source=source,
        provider=provider,
        event_type=event_type,
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
                pipeline._persist_finding(session, finding)
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


@cli.group()
def scheduler() -> None:
    """Pipeline scheduler for continuous monitoring."""


@scheduler.command("start")
@click.option("--interval", "-i", default=60, help="Interval in minutes between pipeline runs")
def scheduler_start(interval: int) -> None:
    """Start the pipeline scheduler."""
    from warlock.pipeline.scheduler import get_scheduler

    sched = get_scheduler(interval_minutes=interval)
    sched.start()

    console.print(f"[green]Scheduler started (interval={interval}m)[/green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")

    import signal
    import time

    stop_event = False

    def handle_signal(sig, frame):
        nonlocal stop_event
        stop_event = True
        sched.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while not stop_event and sched._running:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sched.stop()
        console.print("\n[yellow]Scheduler stopped.[/yellow]")


@scheduler.command("status")
def scheduler_status() -> None:
    """Show scheduler status."""
    from warlock.pipeline.scheduler import get_scheduler

    sched = get_scheduler()
    st = sched.status

    console.print("\n[bold]Scheduler Status[/bold]")
    running_style = "green" if st["running"] else "red"
    console.print(f"  Running:    [{running_style}]{st['running']}[/]")
    console.print(f"  Interval:   {st['interval_minutes']}m")
    console.print(f"  Run count:  {st['run_count']}")
    console.print(f"  Last run:   {st['last_run'] or 'never'}")
    console.print(f"  Next run:   {st['next_run'] or 'n/a'}")
    if st["last_error"]:
        console.print(f"  Last error: [red]{st['last_error']}[/red]")
