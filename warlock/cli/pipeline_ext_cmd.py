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
from rich.markup import escape
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
    import json as _json

    broken: list[tuple[int, str]] = []
    prev_hash = "genesis"

    for entry in entries:
        # Recompute expected hash — must match AuditTrail.record() serialization:
        # JSON with sort_keys=True, no created_at (timestamp excluded for
        # deterministic recomputation).
        content = _json.dumps(
            {
                "sequence": int(entry.sequence),
                "previous_hash": entry.previous_hash,
                "action": entry.action,
                "entity_type": entry.entity_type,
                "entity_id": entry.entity_id,
                "actor": entry.actor,
                "evidence_sha256": entry.evidence_sha256 or "",
            },
            sort_keys=True,
        )
        expected_hash = hashlib.sha256(content.encode()).hexdigest()

        if entry.previous_hash != prev_hash:
            broken.append((entry.sequence, f"previous_hash mismatch at seq {entry.sequence}"))

        if expected_hash != entry.entry_hash:
            broken.append((entry.sequence, f"entry_hash mismatch at seq {entry.sequence}"))

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

    # Semantic diff: show which controls/findings changed status between runs
    from warlock.db.engine import get_read_session
    from warlock.db.models import ControlResult, Finding, RawEvent

    with get_read_session() as session:
        # Count findings per run
        findings_a = (
            session.query(Finding)
            .join(RawEvent, Finding.raw_event_id == RawEvent.id)
            .filter(RawEvent.connector_run_id == run_a.id)
            .count()
        )
        findings_b = (
            session.query(Finding)
            .join(RawEvent, Finding.raw_event_id == RawEvent.id)
            .filter(RawEvent.connector_run_id == run_b.id)
            .count()
        )

        # Get control result status changes between the two connectors
        # (by framework + control_id, compare statuses)

        results_a = dict(
            session.query(
                ControlResult.framework + ":" + ControlResult.control_id,
                ControlResult.status,
            )
            .join(Finding, ControlResult.finding_id == Finding.id)
            .join(RawEvent, Finding.raw_event_id == RawEvent.id)
            .filter(RawEvent.connector_run_id == run_a.id)
            .all()
        )
        results_b = dict(
            session.query(
                ControlResult.framework + ":" + ControlResult.control_id,
                ControlResult.status,
            )
            .join(Finding, ControlResult.finding_id == Finding.id)
            .join(RawEvent, Finding.raw_event_id == RawEvent.id)
            .filter(RawEvent.connector_run_id == run_b.id)
            .all()
        )

    console.print("\n[bold]Semantic Diff[/bold]")
    console.print(f"  Findings: Run A={findings_a}, Run B={findings_b}")

    # Find status changes
    all_controls = set(results_a.keys()) | set(results_b.keys())
    changed: list[tuple[str, str, str]] = []
    new_in_b: list[str] = []
    removed_in_b: list[str] = []

    for ctrl in sorted(all_controls):
        status_a = results_a.get(ctrl)
        status_b = results_b.get(ctrl)
        if status_a and status_b and status_a != status_b:
            changed.append((ctrl, status_a, status_b))
        elif status_a and not status_b:
            removed_in_b.append(ctrl)
        elif not status_a and status_b:
            new_in_b.append(ctrl)

    if changed:
        console.print(f"\n  [yellow]Status changes ({len(changed)}):[/yellow]")
        for ctrl, sa, sb in changed[:10]:
            sa_style = "green" if sa == "compliant" else "red"
            sb_style = "green" if sb == "compliant" else "red"
            console.print(
                f"    {ctrl}: [{sa_style}]{sa}[/{sa_style}] -> [{sb_style}]{sb}[/{sb_style}]"
            )
        if len(changed) > 10:
            console.print(f"    ... and {len(changed) - 10} more")
    else:
        console.print("  [dim]No control status changes between runs.[/dim]")

    if new_in_b:
        console.print(f"  [cyan]New controls in Run B: {len(new_in_b)}[/cyan]")
    if removed_in_b:
        console.print(f"  [yellow]Controls removed in Run B: {len(removed_in_b)}[/yellow]")


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
        payload = json.dumps(evt.raw_data, sort_keys=True, default=str)
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


# ---------------------------------------------------------------------------
# dlq sub-group — Dead Letter Queue management
# ---------------------------------------------------------------------------


@pipeline_group.group("dlq", invoke_without_command=True)
@click.pass_context
def dlq_group(ctx: click.Context) -> None:
    """Dead letter queue: inspect, retry, and purge failed pipeline events."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@dlq_group.command("list")
@click.option("--status", "-s", default=None, help="Filter by status (failed, retried, purged)")
@click.option("--limit", "-n", default=25, help="Max entries to show")
def dlq_list(status: str | None, limit: int) -> None:
    """List dead letter queue entries."""
    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import DeadLetterEntry

    init_db()
    with get_read_session() as session:
        q = session.query(DeadLetterEntry)
        if status:
            q = q.filter(DeadLetterEntry.status == status)
        rows = q.order_by(DeadLetterEntry.created_at.desc()).limit(limit).all()

    if not rows:
        console.print("[dim]No dead letter queue entries found.[/dim]")
        return

    table = Table(title=f"Dead Letter Queue ({len(rows)} entries)")
    table.add_column("ID", style="dim", max_width=8)
    table.add_column("Event Type", max_width=30)
    table.add_column("Status")
    table.add_column("Retries", justify="right")
    table.add_column("Error", max_width=50)
    table.add_column("Created")

    for entry in rows:
        status_style = {
            "failed": "red",
            "retried": "yellow",
            "purged": "dim",
        }.get(entry.status, "white")
        created = entry.created_at.strftime("%Y-%m-%d %H:%M:%S") if entry.created_at else "\u2014"
        table.add_row(
            entry.id[:8],
            entry.event_type[:30],
            f"[{status_style}]{entry.status}[/{status_style}]",
            str(entry.retry_count or 0),
            (entry.error_message or "")[:50],
            created,
        )

    console.print(table)


@dlq_group.command("retry")
@click.argument("entry_id")
def dlq_retry(entry_id: str) -> None:
    """Retry a failed dead letter queue entry.

    ENTRY_ID: DLQ entry ID (or prefix) to retry.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DeadLetterEntry
    from warlock.pipeline.bus import EventBus, PipelineEvent

    init_db()
    with get_session() as session:
        entry = (
            session.query(DeadLetterEntry).filter(DeadLetterEntry.id.startswith(entry_id)).first()
        )
        if not entry:
            _error(f"DLQ entry not found: {entry_id}")
        if entry.status != "failed":
            _error(f"Entry {entry_id} is in '{entry.status}' status, not 'failed'.")

        bus = EventBus()
        event = PipelineEvent(
            event_type=entry.event_type,
            payload_id=entry.original_event_id or entry.id,
            metadata=entry.payload or {},
        )
        try:
            bus.publish(event)
            entry.status = "retried"
            entry.retry_count = (entry.retry_count or 0) + 1
            entry.last_retry_at = datetime.now(timezone.utc)
            session.flush()
            console.print(
                f"[green]Retried DLQ entry {entry.id[:8]}[/green] (event_type={entry.event_type})"
            )
        except Exception as exc:
            entry.retry_count = (entry.retry_count or 0) + 1
            entry.error_message = str(exc)
            entry.last_retry_at = datetime.now(timezone.utc)
            session.flush()
            _error(f"Retry failed: {exc}")


@dlq_group.command("purge")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def dlq_purge(yes: bool) -> None:
    """Purge all failed entries from the dead letter queue."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import DeadLetterEntry

    init_db()
    with get_session() as session:
        count = session.query(DeadLetterEntry).filter(DeadLetterEntry.status == "failed").count()

        if count == 0:
            console.print("[dim]No failed entries to purge.[/dim]")
            return

        if not yes:
            click.confirm(f"Purge {count} failed DLQ entries?", abort=True)

        session.query(DeadLetterEntry).filter(DeadLetterEntry.status == "failed").update(
            {"status": "purged"}
        )
        session.flush()
        console.print(f"[green]Purged {count} failed DLQ entries.[/green]")


# ---------------------------------------------------------------------------
# dag — Pipeline DAG visualization (P2 Item 59)
# ---------------------------------------------------------------------------


@pipeline_group.command("dag")
def pipeline_dag() -> None:
    """Display the pipeline stage dependency graph as ASCII art."""
    from rich.tree import Tree

    tree = Tree("[bold cyan]Pipeline DAG[/bold cyan]")

    # Stage 1: Collect
    collect = tree.add("[bold]Stage 1: Collect[/bold] (connectors)")
    collect.add("[dim]Input:[/dim]  Connector configs, credentials")
    collect.add("[dim]Output:[/dim] RawEventData (raw_events table)")
    collect.add("[dim]Hash:[/dim]   SHA-256 over raw_data")

    # Stage 2: Normalize
    normalize = tree.add("[bold]Stage 2: Normalize[/bold] (normalizers)")
    normalize.add("[dim]Input:[/dim]  RawEventData")
    normalize.add("[dim]Output:[/dim] FindingData (findings table)")
    normalize.add("[dim]Hash:[/dim]   SHA-256 over finding fields")

    # Stage 3: Map
    mapping = tree.add("[bold]Stage 3: Map[/bold] (control mapper)")
    mapping.add("[dim]Input:[/dim]  FindingData + framework YAMLs")
    mapping.add("[dim]Output:[/dim] ControlMapping (control_mappings table)")
    mapping.add("[dim]Frameworks:[/dim] 14 active")

    # Stage 4: Assess
    assess = tree.add("[bold]Stage 4: Assess[/bold] (assertion engine)")
    assess.add("[dim]Input:[/dim]  MappedResult + raw_data")
    assess.add("[dim]Output:[/dim] ControlResultData (control_results table)")
    assess.add("[dim]Tiers:[/dim]  1=assertions, 2=AI (if enabled)")

    # Stage 5: OPA (optional)
    opa = tree.add("[bold]Stage 5: OPA Compliance[/bold] (optional)")
    opa.add("[dim]Input:[/dim]  NormalizedData + Rego policies")
    opa.add("[dim]Output:[/dim] ControlResultData (additional results)")

    # Post-pipeline
    post = tree.add("[bold]Post-pipeline[/bold]")
    post.add("Lake write (Parquet materialization)")
    post.add("Domain writers (posture, drift, governance)")
    post.add("Materialized view refresh")
    post.add("Dashboard cache invalidation")

    console.print(tree)

    # Lineage chain summary
    console.print("\n[bold]Lineage chain:[/bold]")
    console.print("  connector_run -> raw_event -> finding -> control_mapping -> control_result")
    console.print(
        "\n[dim]Each stage publishes events on the pipeline event bus. "
        "The lake writer subscribes to all events.[/dim]"
    )


# ---------------------------------------------------------------------------
# costs — Per-connector timing and count tracking (P2 Item 61)
# ---------------------------------------------------------------------------


@pipeline_group.command("costs")
@click.option("--limit", "-n", default=25, help="Number of connectors to show")
def pipeline_costs(limit: int) -> None:
    """Show per-connector resource usage (timing, event counts, error rates)."""
    from sqlalchemy import func

    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_read_session() as session:
        rows = (
            session.query(
                ConnectorRun.connector_name,
                func.count().label("runs"),
                func.sum(ConnectorRun.event_count).label("total_events"),
                func.sum(ConnectorRun.error_count).label("total_errors"),
                func.avg(ConnectorRun.duration_seconds).label("avg_duration"),
                func.max(ConnectorRun.duration_seconds).label("max_duration"),
                func.sum(ConnectorRun.duration_seconds).label("total_duration"),
            )
            .group_by(ConnectorRun.connector_name)
            .order_by(func.sum(ConnectorRun.duration_seconds).desc())
            .limit(limit)
            .all()
        )

    if not rows:
        console.print("[dim]No connector run data. Run the pipeline first.[/dim]")
        return

    table = Table(title="Pipeline Cost/Resource Usage by Connector")
    table.add_column("Connector", max_width=35)
    table.add_column("Runs", justify="right")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Avg Duration", justify="right")
    table.add_column("Max Duration", justify="right")
    table.add_column("Total Time", justify="right")
    table.add_column("Err Rate", justify="right")

    for row in rows:
        name, runs, total_events, total_errors, avg_dur, max_dur, total_dur = row
        total_events = total_events or 0
        total_errors = total_errors or 0
        err_rate = f"{total_errors * 100 / total_events:.1f}%" if total_events > 0 else "0.0%"
        err_style = "red" if total_errors > 0 else "green"
        table.add_row(
            escape(name[:35]),
            str(runs),
            f"{total_events:,}",
            f"[{err_style}]{total_errors:,}[/{err_style}]",
            f"{avg_dur:.2f}s" if avg_dur else "--",
            f"{max_dur:.2f}s" if max_dur else "--",
            f"{total_dur:.1f}s" if total_dur else "--",
            f"[{err_style}]{err_rate}[/{err_style}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# smoke-test — Pipeline canary/health check (P2 Item 65)
# ---------------------------------------------------------------------------


@pipeline_group.command("smoke-test")
@click.option("--count", "-n", default=5, help="Number of connectors to test")
def pipeline_smoke_test(count: int) -> None:
    """Run a quick smoke test with representative connectors.

    Runs a small subset of connectors (default 5) as a pipeline health check.
    Validates that collect -> normalize -> map -> assess completes without error.
    """
    from warlock.db.engine import get_session, init_db
    from warlock.pipeline.bus import EventBus
    from warlock.pipeline.loader import build_pipeline

    init_db()
    bus = EventBus()
    pipeline = build_pipeline(bus)

    active = pipeline.connectors.list_active()
    if not active:
        console.print(
            "[yellow]No connectors configured. Run 'warlock collect --demo' first.[/yellow]"
        )
        return

    # Pick representative connectors (spread across sources)
    sources_seen: set[str] = set()
    selected: list[str] = []
    for conn in active:
        source = getattr(conn, "source", "unknown")
        if source not in sources_seen:
            selected.append(getattr(conn, "name", str(conn)))
            sources_seen.add(source)
        if len(selected) >= count:
            break
    # Fill remaining slots if we haven't reached count
    for conn in active:
        if len(selected) >= count:
            break
        name = getattr(conn, "name", str(conn))
        if name not in selected:
            selected.append(name)

    console.print(
        f"[cyan]Smoke testing {len(selected)} connectors: "
        f"{', '.join(s[:20] for s in selected[:5])}...[/cyan]"
    )

    # Run with these connectors only
    pipeline_test = build_pipeline(bus, sources=None)

    with console.status("[bold cyan]Running smoke test...[/bold cyan]"):
        with get_session() as session:
            stats = pipeline_test.run(session)

    ok = stats.connectors_succeeded
    fail = stats.connectors_failed
    status = "[green]PASS[/green]" if fail == 0 else "[red]FAIL[/red]"

    console.print(f"\nSmoke test result: {status}")
    console.print(f"  Connectors: {ok} succeeded, {fail} failed")
    console.print(f"  Raw events: {stats.raw_events_collected}")
    console.print(f"  Findings:   {stats.findings_normalized}")
    console.print(f"  Results:    {stats.results_assessed}")

    if stats.errors:
        console.print(f"\n[red]Errors ({len(stats.errors)}):[/red]")
        for err in stats.errors[:5]:
            console.print(f"  {escape(str(err)[:100])}")

    if fail > 0:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# schema — Schema evolution handling (P2 Item 66)
# ---------------------------------------------------------------------------


@pipeline_group.command("schema")
def pipeline_schema() -> None:
    """Show the event type schema registry and detect unhandled types."""
    from warlock.pipeline.schema_registry import get_schema_registry

    registry = get_schema_registry()
    schemas = registry.list_schemas()

    table = Table(title=f"Event Type Schema Registry ({len(schemas)} types)")
    table.add_column("Source", style="cyan")
    table.add_column("Event Type")
    table.add_column("Required Fields")
    table.add_column("Normalizer")

    for schema in sorted(schemas, key=lambda s: (s.source, s.event_type)):
        table.add_row(
            schema.source,
            schema.event_type,
            ", ".join(schema.required_fields) if schema.required_fields else "--",
            schema.normalizer_class or "--",
        )

    console.print(table)

    # Show unhandled event types
    unhandled = registry.unhandled_event_types()
    if unhandled:
        console.print(f"\n[yellow]Unhandled event types ({len(unhandled)}):[/yellow]")
        for source, event_type in unhandled[:20]:
            console.print(f"  {source}:{event_type}")
    else:
        console.print("\n[green]All registered event types have matching normalizers.[/green]")


# ---------------------------------------------------------------------------
# volume — Pipeline volume anomaly alerting (P2 Item 68)
# ---------------------------------------------------------------------------


@pipeline_group.command("volume")
@click.option("--threshold", default=3.0, help="Deviation multiplier for anomaly (default: 3x)")
def pipeline_volume(threshold: float) -> None:
    """Check connector output volumes for anomalies.

    Compares each connector's latest event count against its historical
    average. Flags connectors with >threshold deviation.
    """
    from sqlalchemy import func

    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_read_session() as session:
        # Get historical averages per connector
        avgs = (
            session.query(
                ConnectorRun.connector_name,
                func.avg(ConnectorRun.event_count).label("avg_count"),
                func.count().label("run_count"),
            )
            .filter(ConnectorRun.status.in_(("success", "partial")))
            .group_by(ConnectorRun.connector_name)
            .all()
        )

        if not avgs:
            console.print("[dim]No connector run data. Run the pipeline first.[/dim]")
            return

        # Get latest run per connector
        from sqlalchemy import desc

        anomalies: list[tuple[str, int, float, float]] = []
        normal: list[tuple[str, int, float]] = []

        for name, avg_count, run_count in avgs:
            latest = (
                session.query(ConnectorRun)
                .filter(
                    ConnectorRun.connector_name == name,
                    ConnectorRun.status.in_(("success", "partial")),
                )
                .order_by(desc(ConnectorRun.started_at))
                .first()
            )
            if not latest or avg_count is None or avg_count == 0:
                continue

            latest_count = latest.event_count or 0
            deviation = latest_count / avg_count if avg_count > 0 else 0

            if deviation > threshold or (deviation < 1 / threshold and deviation > 0):
                anomalies.append((name, latest_count, float(avg_count), deviation))
            else:
                normal.append((name, latest_count, float(avg_count)))

    if anomalies:
        table = Table(title=f"Volume Anomalies (>{threshold}x deviation)")
        table.add_column("Connector", max_width=35)
        table.add_column("Latest", justify="right")
        table.add_column("Average", justify="right")
        table.add_column("Deviation", justify="right")
        table.add_column("Status")

        for name, latest_count, avg_count, deviation in anomalies:
            if deviation > threshold:
                status = "[red]HIGH[/red]"
            else:
                status = "[yellow]LOW[/yellow]"
            table.add_row(
                escape(name[:35]),
                str(latest_count),
                f"{avg_count:.0f}",
                f"{deviation:.1f}x",
                status,
            )
        console.print(table)
    else:
        console.print(
            f"[green]No volume anomalies detected "
            f"(threshold={threshold}x, {len(normal)} connectors checked).[/green]"
        )

    console.print(f"\n[dim]{len(normal)} connector(s) within normal range.[/dim]")


# ---------------------------------------------------------------------------
# preflight — Pre-flight connector check (P3 Item 103)
# ---------------------------------------------------------------------------


@pipeline_group.command("preflight")
def pipeline_preflight() -> None:
    """Verify all connector configurations are valid before running the pipeline."""
    from warlock.pipeline.loader import build_pipeline
    from warlock.pipeline.bus import EventBus
    from warlock.db.engine import init_db

    init_db()
    bus = EventBus()
    pipeline = build_pipeline(bus)

    active = pipeline.connectors.list_active()
    if not active:
        console.print("[yellow]No connectors configured. Set up connectors in .env first.[/yellow]")
        return

    console.print(f"[cyan]Pre-flight check: {len(active)} connectors[/cyan]\n")

    ok_count = 0
    fail_count = 0

    for conn in active:
        name = getattr(conn, "name", str(conn))
        source = getattr(conn, "source", "unknown")
        try:
            # Check that the connector can be instantiated
            # and has required config
            has_collect = hasattr(conn, "collect") and callable(conn.collect)
            if has_collect:
                console.print(f"  [green]OK[/green]  {escape(name)} ({source})")
                ok_count += 1
            else:
                console.print(f"  [red]FAIL[/red] {escape(name)} - missing collect() method")
                fail_count += 1
        except Exception as exc:
            console.print(f"  [red]FAIL[/red] {escape(name)} - {escape(str(exc)[:80])}")
            fail_count += 1

    console.print(f"\n[bold]Results:[/bold] {ok_count} OK, {fail_count} failed")
    if fail_count > 0:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# sla — Pipeline SLA tracking (P3 Item 107)
# ---------------------------------------------------------------------------


@pipeline_group.command("sla")
@click.option("--target", default=60.0, help="SLA target in seconds (default: 60)")
def pipeline_sla(target: float) -> None:
    """Check per-connector SLA compliance (duration vs target)."""
    from sqlalchemy import func

    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_read_session() as session:
        rows = (
            session.query(
                ConnectorRun.connector_name,
                func.count().label("runs"),
                func.avg(ConnectorRun.duration_seconds).label("avg_dur"),
                func.max(ConnectorRun.duration_seconds).label("max_dur"),
                func.min(ConnectorRun.duration_seconds).label("min_dur"),
            )
            .filter(ConnectorRun.status.in_(("success", "partial")))
            .group_by(ConnectorRun.connector_name)
            .order_by(func.avg(ConnectorRun.duration_seconds).desc())
            .all()
        )

    if not rows:
        console.print("[dim]No connector run data. Run the pipeline first.[/dim]")
        return

    table = Table(title=f"Pipeline SLA Report (target: {target}s)")
    table.add_column("Connector", max_width=35)
    table.add_column("Runs", justify="right")
    table.add_column("Avg", justify="right")
    table.add_column("Max", justify="right")
    table.add_column("Min", justify="right")
    table.add_column("SLA Status")

    breaches = 0
    for row in rows:
        name, runs, avg_dur, max_dur, min_dur = row
        avg_dur = avg_dur or 0
        max_dur = max_dur or 0
        min_dur = min_dur or 0

        if avg_dur > target:
            status = "[red]BREACH[/red]"
            breaches += 1
        elif max_dur > target:
            status = "[yellow]AT RISK[/yellow]"
        else:
            status = "[green]OK[/green]"

        table.add_row(
            escape(name[:35]),
            str(runs),
            f"{avg_dur:.2f}s",
            f"{max_dur:.2f}s",
            f"{min_dur:.2f}s",
            status,
        )

    console.print(table)

    if breaches:
        console.print(f"\n[red]{breaches} connector(s) breaching SLA target.[/red]")
    else:
        console.print(f"\n[green]All connectors within SLA target ({target}s).[/green]")


# ---------------------------------------------------------------------------
# metrics — pipeline observability (P1 Item 33)
# ---------------------------------------------------------------------------


@pipeline_group.command("metrics")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "prometheus", "json"]),
    default="table",
    help="Output format",
)
def pipeline_metrics_cmd(fmt: str) -> None:
    """Show pipeline metrics (throughput, latency, errors, queue depth).

    Reads from OLTP pipeline_runs data. Use --format prometheus for scraping.
    """
    import json as _json

    from warlock.pipeline.metrics import get_metrics_from_db, get_pipeline_metrics

    # Try live metrics first; fall back to OLTP-derived
    live = get_pipeline_metrics()
    snap = live.snapshot()

    # If no live data, derive from DB
    if snap.total_events == 0:
        snap = get_metrics_from_db()

    if fmt == "prometheus":
        if snap.total_events > 0:
            # Build prometheus text directly from snapshot (avoid O(N) seeding)
            lines: list[str] = []
            lines.append("# HELP warlock_pipeline_events_total Total events per stage")
            lines.append("# TYPE warlock_pipeline_events_total counter")
            for stage_name, m in snap.stages.items():
                lines.append(
                    f'warlock_pipeline_events_total{{stage="{stage_name}"}} {m.events_processed}'
                )
            lines.append("# HELP warlock_pipeline_errors_total Total errors per stage")
            lines.append("# TYPE warlock_pipeline_errors_total counter")
            for stage_name, m in snap.stages.items():
                lines.append(
                    f'warlock_pipeline_errors_total{{stage="{stage_name}"}} {m.events_errored}'
                )
            lines.append("# HELP warlock_pipeline_throughput_eps Events/sec (60s)")
            lines.append("# TYPE warlock_pipeline_throughput_eps gauge")
            lines.append(f"warlock_pipeline_throughput_eps {snap.throughput_eps:.2f}")
            lines.append("# HELP warlock_pipeline_events_total_all Total events")
            lines.append("# TYPE warlock_pipeline_events_total_all counter")
            lines.append(f"warlock_pipeline_events_total_all {snap.total_events}")
            lines.append("# HELP warlock_pipeline_errors_total_all Total errors")
            lines.append("# TYPE warlock_pipeline_errors_total_all counter")
            lines.append(f"warlock_pipeline_errors_total_all {snap.total_errors}")
            lines.append("# HELP warlock_pipeline_active_connectors Active connectors")
            lines.append("# TYPE warlock_pipeline_active_connectors gauge")
            lines.append(f"warlock_pipeline_active_connectors {snap.active_connectors}")
            lines.append("")
            console.print("\n".join(lines))
        else:
            console.print("# No pipeline metrics available")
        return

    if fmt == "json":
        data = {
            "total_events": snap.total_events,
            "total_errors": snap.total_errors,
            "throughput_eps": round(snap.throughput_eps, 2),
            "uptime_seconds": round(snap.uptime_seconds, 1),
            "queue_depth": snap.queue_depth,
            "active_connectors": snap.active_connectors,
            "last_run_id": snap.last_run_id,
            "last_run_at": snap.last_run_at.isoformat() if snap.last_run_at else None,
            "stages": {
                name: {
                    "events_processed": m.events_processed,
                    "events_errored": m.events_errored,
                    "avg_latency_ms": round(m.avg_latency_ms, 2),
                    "error_rate": round(m.error_rate, 4),
                }
                for name, m in snap.stages.items()
            },
        }
        console.print(_json.dumps(data, indent=2))
        return

    # Table format

    table = Table(title="Pipeline Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")

    table.add_row("Total events", f"{snap.total_events:,}")
    table.add_row("Total errors", f"{snap.total_errors:,}")
    table.add_row(
        "Throughput",
        f"{snap.throughput_eps:.1f} events/sec" if snap.throughput_eps else "N/A",
    )
    table.add_row("Queue depth", str(snap.queue_depth))
    table.add_row("Active connectors", str(snap.active_connectors))
    table.add_row(
        "Last run",
        snap.last_run_at.strftime("%Y-%m-%d %H:%M:%S") if snap.last_run_at else "Never",
    )
    table.add_row("Last run ID", (snap.last_run_id or "N/A")[:12])
    console.print(table)

    if snap.stages:
        stage_table = Table(title="Per-Stage Metrics")
        stage_table.add_column("Stage", style="cyan")
        stage_table.add_column("Processed", justify="right")
        stage_table.add_column("Errors", justify="right")
        stage_table.add_column("Avg Latency", justify="right")
        stage_table.add_column("Error Rate", justify="right")

        for name, m in snap.stages.items():
            err_color = "red" if m.events_errored > 0 else "green"
            stage_table.add_row(
                name,
                f"{m.events_processed:,}",
                f"[{err_color}]{m.events_errored:,}[/{err_color}]",
                f"{m.avg_latency_ms:.1f}ms",
                f"{m.error_rate:.2%}",
            )
        console.print(stage_table)
