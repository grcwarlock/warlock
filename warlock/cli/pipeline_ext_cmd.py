"""Extended pipeline commands: status, history, run, verify-chain, stats, errors,
schedule (show/set), replay, compare, hash-verify.

The existing pipeline.py registers flat commands (init, collect, ingest) on cli and a
'scheduler' sub-group. This module registers a 'pipeline' group, which is distinct from
the flat commands because Click groups and flat commands occupy the same namespace.

IMPORTANT: Since pipeline.py has no 'pipeline' group (only flat commands and a 'scheduler'
group), there is no collision. The new group named 'pipeline' will be the only group-level
'pipeline' command.
"""

from __future__ import annotations

from datetime import datetime, timezone

import click
from rich.table import Table

from warlock.cli import cli, console, _error


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("pipeline", invoke_without_command=True)
@click.pass_context
def pipeline_group(ctx: click.Context) -> None:
    """Pipeline run management: status, history, verification, replay, and scheduling."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@pipeline_group.command("status")
@click.option("--limit", "-n", default=10, help="Number of recent runs to show")
def pipeline_status(limit: int) -> None:
    """Show the status of recent pipeline runs."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        rows = (
            session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(limit).all()
        )

    if not rows:
        console.print("[dim]No pipeline runs found. Run 'warlock collect' to start.[/dim]")
        return

    table = Table(title=f"Recent Pipeline Runs (last {limit})")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Connector", max_width=30)
    table.add_column("Source")
    table.add_column("Provider")
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Duration")
    table.add_column("Started")

    for run in rows:
        status_style = {
            "success": "green",
            "running": "cyan",
            "partial": "yellow",
            "error": "red",
        }.get(run.status, "white")
        dur = f"{run.duration_seconds:.1f}s" if run.duration_seconds else "\u2014"
        started = run.started_at.strftime("%Y-%m-%d %H:%M") if run.started_at else "\u2014"
        table.add_row(
            run.id[:8],
            run.connector_name[:30],
            run.source,
            run.provider,
            f"[{status_style}]{run.status}[/{status_style}]",
            str(run.event_count or 0),
            str(run.error_count or 0),
            dur,
            started,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@pipeline_group.command("history")
@click.option("--connector", "-c", default=None, help="Filter by connector name")
@click.option("--source", "-s", default=None, help="Filter by source (e.g. aws, okta)")
@click.option("--status", default=None, help="Filter by status (success, error, partial)")
@click.option("--limit", "-n", default=25, help="Max results")
def pipeline_history(
    connector: str | None,
    source: str | None,
    status: str | None,
    limit: int,
) -> None:
    """Show full pipeline run history with filters."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        q = session.query(ConnectorRun)
        if connector:
            q = q.filter(ConnectorRun.connector_name.ilike(f"%{connector}%"))
        if source:
            q = q.filter(ConnectorRun.source == source)
        if status:
            q = q.filter(ConnectorRun.status == status)
        rows = q.order_by(ConnectorRun.started_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No runs match the given filters.[/dim]")
        return

    table = Table(title=f"Pipeline History ({len(rows)} runs)")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Connector", max_width=35)
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Duration")
    table.add_column("Started")

    for run in rows:
        status_style = {
            "success": "green",
            "running": "cyan",
            "partial": "yellow",
            "error": "red",
        }.get(run.status, "white")
        dur = f"{run.duration_seconds:.1f}s" if run.duration_seconds else "\u2014"
        started = run.started_at.strftime("%Y-%m-%d %H:%M:%S") if run.started_at else "\u2014"
        table.add_row(
            run.id[:8],
            run.connector_name[:35],
            run.source,
            f"[{status_style}]{run.status}[/{status_style}]",
            str(run.event_count or 0),
            str(run.error_count or 0),
            dur,
            started,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@pipeline_group.command("run")
@click.option("--source", "-s", multiple=True, help="Limit to specific sources (e.g. aws, okta)")
def pipeline_run(source: tuple[str, ...]) -> None:
    """Trigger a new pipeline run (collect -> normalize -> map -> assess).

    This is an alias for 'warlock collect' exposed under the pipeline group.
    """
    from warlock.cli import _print_stats
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline, register_lake_writer

    init_db()
    bus = EventBus()
    lake_writer = register_lake_writer(bus)
    pipeline = build_pipeline(bus, sources=source or None)

    with get_session() as session:
        stats = pipeline.run(session)

    if lake_writer is not None:
        with get_session() as lake_session:
            lake_writer.flush(stats.run_id, lake_session)

    _print_stats(stats)
    if stats.errors:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# verify-chain
# ---------------------------------------------------------------------------


@pipeline_group.command("verify-chain")
@click.option("--limit", "-n", default=100, help="Number of most recent audit entries to verify")
def verify_chain(limit: int) -> None:
    """Verify the SHA-256 hash chain integrity of the audit trail."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import AuditEntry

    init_db()
    with get_session() as session:
        entries = session.query(AuditEntry).order_by(AuditEntry.sequence.asc()).limit(limit).all()

    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        return

    import hashlib

    broken: list[tuple[int, str]] = []
    prev_hash = "genesis"

    for entry in entries:
        # Recompute expected hash for this entry
        payload = (
            f"{entry.sequence}:{entry.previous_hash}:{entry.action}:"
            f"{entry.entity_type}:{entry.entity_id}:{entry.actor}"
        )
        hashlib.sha256(payload.encode()).hexdigest()

        if entry.previous_hash != prev_hash:
            broken.append((entry.sequence, f"previous_hash mismatch at seq {entry.sequence}"))

        prev_hash = entry.entry_hash

    if broken:
        console.print(f"[red]Chain broken at {len(broken)} point(s):[/red]")
        for seq, reason in broken[:10]:
            console.print(f"  seq {seq}: {reason}")
    else:
        console.print(
            f"[green]Chain intact:[/green] {len(entries)} entries verified (seq "
            f"{entries[0].sequence} \u2013 {entries[-1].sequence})"
        )


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@pipeline_group.command("stats")
@click.option("--framework", "-f", default=None, help="Filter by framework")
def pipeline_stats(framework: str | None) -> None:
    """Show aggregate pipeline statistics across all runs."""
    from sqlalchemy import func

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, ControlResult, Finding, RawEvent

    init_db()
    with get_session() as session:
        total_runs = session.query(ConnectorRun).count()
        success_runs = session.query(ConnectorRun).filter(ConnectorRun.status == "success").count()
        error_runs = session.query(ConnectorRun).filter(ConnectorRun.status == "error").count()
        total_raw = session.query(RawEvent).count()
        total_findings = session.query(Finding).count()

        q = session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)
        total_results = q.count()
        compliant = q.filter(ControlResult.status == "compliant").count()
        non_compliant = q.filter(ControlResult.status == "non_compliant").count()

        avg_dur = session.query(func.avg(ConnectorRun.duration_seconds)).scalar()

    console.print("\n[bold]Pipeline Aggregate Statistics[/bold]\n")
    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total connector runs", str(total_runs))
    table.add_row("  Successful", f"[green]{success_runs}[/green]")
    table.add_row("  Errors", f"[red]{error_runs}[/red]")
    table.add_row("Raw events collected", f"{total_raw:,}")
    table.add_row("Findings normalized", f"{total_findings:,}")
    table.add_row(
        "Control results" + (f" [{framework}]" if framework else ""), f"{total_results:,}"
    )
    table.add_row("  Compliant", f"[green]{compliant:,}[/green]")
    table.add_row("  Non-compliant", f"[red]{non_compliant:,}[/red]")
    if avg_dur is not None:
        table.add_row("Avg run duration", f"{avg_dur:.1f}s")

    console.print(table)


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


@pipeline_group.command("errors")
@click.option("--limit", "-n", default=20, help="Max runs to show errors from")
@click.option("--connector", "-c", default=None, help="Filter by connector name")
def pipeline_errors(limit: int, connector: str | None) -> None:
    """Show error details from recent pipeline runs."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        q = session.query(ConnectorRun).filter(ConnectorRun.error_count > 0)
        if connector:
            q = q.filter(ConnectorRun.connector_name.ilike(f"%{connector}%"))
        rows = q.order_by(ConnectorRun.started_at.desc()).limit(limit).all()

    if not rows:
        console.print("[green]No pipeline errors found.[/green]")
        return

    for run in rows:
        started = run.started_at.strftime("%Y-%m-%d %H:%M:%S") if run.started_at else "?"
        console.print(
            f"\n[yellow]{run.connector_name}[/yellow] "
            f"[dim]{run.id[:8]}[/dim] — {started} — "
            f"[red]{run.error_count} error(s)[/red]"
        )
        errors = run.errors or []
        for err in errors[:5]:
            console.print(f"  [dim]\u2022[/dim] {err}")
        if len(errors) > 5:
            console.print(f"  [dim]... and {len(errors) - 5} more[/dim]")


# ---------------------------------------------------------------------------
# schedule sub-group
# ---------------------------------------------------------------------------


@pipeline_group.group("schedule", invoke_without_command=True)
@click.pass_context
def schedule_group(ctx: click.Context) -> None:
    """Manage the pipeline scheduler interval and view schedule details."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@schedule_group.command("show")
def schedule_show() -> None:
    """Show current scheduler configuration."""
    from warlock.pipeline.scheduler import get_scheduler

    sched = get_scheduler()
    st = sched.status

    console.print("\n[bold]Scheduler Configuration[/bold]")
    running_style = "green" if st["running"] else "dim"
    console.print(f"  Running:   [{running_style}]{st['running']}[/{running_style}]")
    console.print(f"  Interval:  {st['interval_minutes']} minutes")
    console.print(f"  Run count: {st['run_count']}")
    console.print(f"  Last run:  {st['last_run'] or 'never'}")
    console.print(f"  Next run:  {st['next_run'] or 'n/a'}")
    if st.get("last_error"):
        console.print(f"  Last error: [red]{st['last_error']}[/red]")


@schedule_group.command("set")
@click.option(
    "--interval",
    "-i",
    required=True,
    type=int,
    help="New interval in minutes between pipeline runs",
)
def schedule_set(interval: int) -> None:
    """Set the scheduler interval (requires a running scheduler)."""
    if interval < 1:
        _error("Interval must be at least 1 minute.")

    from warlock.pipeline.scheduler import get_scheduler

    get_scheduler(interval_minutes=interval)
    console.print(f"[green]Scheduler interval set to {interval} minute(s).[/green]")
    console.print(
        "[dim]Note: this affects the next scheduler instance. Restart 'warlock scheduler start' "
        "to apply.[/dim]"
    )


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


@pipeline_group.command("replay")
@click.argument("run_id")
def pipeline_replay(run_id: str) -> None:
    """Replay normalisation and assessment for an existing raw event collection run.

    RUN_ID: Connector run ID (or prefix) to replay from stored raw events.
    """
    from warlock.cli import _print_stats
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, RawEvent
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline
    from warlock.pipeline.orchestrator import PipelineRunStats

    init_db()
    with get_session() as session:
        run = session.query(ConnectorRun).filter(ConnectorRun.id.startswith(run_id)).first()
        if not run:
            _error(f"Connector run not found: {run_id}")

        raw_events = session.query(RawEvent).filter(RawEvent.connector_run_id == run.id).all()
        if not raw_events:
            _error(f"No raw events found for run {run_id}.")

        console.print(
            f"[cyan]Replaying {len(raw_events)} raw events from run "
            f"{run.connector_name} ({run.id[:8]})[/cyan]"
        )

        bus = EventBus()
        pipeline = build_pipeline(bus)
        stats = PipelineRunStats()

        for raw_event_row in raw_events:
            # Reconstruct a RawEvent-like object for the normalizer
            from warlock.connectors.base import RawEvent as ConnRawEvent, SourceType

            raw = ConnRawEvent(
                source=raw_event_row.source,
                source_type=SourceType(raw_event_row.source_type),
                provider=raw_event_row.provider,
                event_type=raw_event_row.event_type,
                raw_data=raw_event_row.raw_data,
            )

            findings = pipeline.normalizers.normalize(raw)
            for finding in findings:
                finding.raw_event_id = raw_event_row.id
                pipeline._persist_finding(session, finding)
                stats.findings_normalized += 1

                mapped = pipeline.mapper.map(finding)
                for mapping in mapped.mappings:
                    pipeline._persist_mapping(session, mapping)
                    stats.controls_mapped += 1

                results = pipeline.assessor.assess(mapped, raw_data=raw_event_row.raw_data)
                for result in results:
                    pipeline._persist_result(session, result)
                    stats.results_assessed += 1

            stats.raw_events_collected += 1

        stats.connectors_succeeded = 1
        session.flush()

    stats.completed_at = datetime.now(timezone.utc)
    _print_stats(stats)


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------


@pipeline_group.command("compare")
@click.argument("run_id_a")
@click.argument("run_id_b")
def pipeline_compare(run_id_a: str, run_id_b: str) -> None:
    """Compare two pipeline runs side-by-side.

    RUN_ID_A: First run ID (or prefix)\n
    RUN_ID_B: Second run ID (or prefix)
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        run_a = session.query(ConnectorRun).filter(ConnectorRun.id.startswith(run_id_a)).first()
        run_b = session.query(ConnectorRun).filter(ConnectorRun.id.startswith(run_id_b)).first()

        if not run_a:
            _error(f"Run not found: {run_id_a}")
        if not run_b:
            _error(f"Run not found: {run_id_b}")

    table = Table(title="Pipeline Run Comparison")
    table.add_column("Metric", style="cyan")
    table.add_column(f"Run A ({run_a.id[:8]})", justify="right")
    table.add_column(f"Run B ({run_b.id[:8]})", justify="right")
    table.add_column("Delta", justify="right")

    def _delta(a: int | float | None, b: int | float | None) -> str:
        if a is None or b is None:
            return "\u2014"
        diff = (b or 0) - (a or 0)
        if diff > 0:
            return f"[green]+{diff}[/green]"
        elif diff < 0:
            return f"[red]{diff}[/red]"
        return "0"

    table.add_row("Connector", run_a.connector_name[:25], run_b.connector_name[:25], "")
    table.add_row("Source", run_a.source, run_b.source, "")
    table.add_row("Status", run_a.status, run_b.status, "")
    table.add_row(
        "Events collected",
        str(run_a.event_count or 0),
        str(run_b.event_count or 0),
        _delta(run_a.event_count, run_b.event_count),
    )
    table.add_row(
        "Error count",
        str(run_a.error_count or 0),
        str(run_b.error_count or 0),
        _delta(run_a.error_count, run_b.error_count),
    )
    dur_a = f"{run_a.duration_seconds:.1f}s" if run_a.duration_seconds else "\u2014"
    dur_b = f"{run_b.duration_seconds:.1f}s" if run_b.duration_seconds else "\u2014"
    table.add_row(
        "Duration",
        dur_a,
        dur_b,
        _delta(run_a.duration_seconds, run_b.duration_seconds),
    )
    started_a = run_a.started_at.strftime("%Y-%m-%d %H:%M") if run_a.started_at else "\u2014"
    started_b = run_b.started_at.strftime("%Y-%m-%d %H:%M") if run_b.started_at else "\u2014"
    table.add_row("Started", started_a, started_b, "")

    console.print(table)


# ---------------------------------------------------------------------------
# hash-verify
# ---------------------------------------------------------------------------


@pipeline_group.command("hash-verify")
@click.argument("run_id")
def hash_verify(run_id: str) -> None:
    """Verify SHA-256 integrity of all raw events in a connector run.

    RUN_ID: Connector run ID (or prefix) to verify.
    """
    import hashlib
    import json

    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun, RawEvent

    init_db()
    with get_session() as session:
        run = session.query(ConnectorRun).filter(ConnectorRun.id.startswith(run_id)).first()
        if not run:
            _error(f"Connector run not found: {run_id}")

        events = session.query(RawEvent).filter(RawEvent.connector_run_id == run.id).all()

    if not events:
        console.print("[dim]No raw events found for this run.[/dim]")
        return

    ok = 0
    bad: list[str] = []

    for evt in events:
        payload = json.dumps(evt.raw_data, sort_keys=True, separators=(",", ":"))
        computed = hashlib.sha256(payload.encode()).hexdigest()
        if computed == evt.sha256:
            ok += 1
        else:
            bad.append(evt.id[:8])

    if bad:
        console.print(f"[red]Hash mismatch for {len(bad)} event(s):[/red]")
        for event_id in bad[:10]:
            console.print(f"  [dim]\u2022[/dim] {event_id}")
    else:
        console.print(
            f"[green]All {ok} raw events verified:[/green] SHA-256 hashes match for run "
            f"{run.connector_name} ({run.id[:8]})"
        )
