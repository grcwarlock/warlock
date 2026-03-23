"""Connector management commands.

Provides inspection, testing, collection, and operational commands
for the 82 registered source connectors.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict

import click
from rich.table import Table

from warlock.cli import cli, console, _error


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


@cli.group("connectors", invoke_without_command=True)
@click.pass_context
def connectors(ctx: click.Context) -> None:
    """Manage and operate source connectors."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(connectors_list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_registry():
    """Return the global connector registry, with all connectors loaded."""
    from warlock.connectors.base import registry

    # Trigger registration of all connectors if not already done
    try:
        import warlock.connectors  # noqa: F401 — side-effect: registers connectors
    except Exception:
        pass
    # Also attempt to load demo seed configs so the registry has entries in dev
    return registry


def _get_pipeline_configs() -> list[dict]:
    """Return connector config dicts sourced from demo_seed definitions.

    Falls back to an empty list if the configs module is unavailable.
    """
    configs: list[dict] = []
    try:
        from scripts.demo_seed import CONNECTOR_CONFIGS  # type: ignore[import]

        configs = [c if isinstance(c, dict) else vars(c) for c in CONNECTOR_CONFIGS]
    except Exception:
        pass
    return configs


def _db_connector_names() -> list[str]:
    """Return unique connector names recorded in the DB."""
    try:
        from warlock.db.engine import get_session, init_db
        from warlock.db.models import ConnectorRun

        init_db()
        with get_session() as session:
            rows = session.query(ConnectorRun.connector_name).distinct().all()
        return [r[0] for r in rows]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@connectors.command("list")
@click.option("--source-type", "-t", default=None, help="Filter by source type")
@click.option("--provider", "-p", default=None, help="Filter by provider")
@click.option("--enabled/--disabled", default=None, help="Filter by enabled state")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def connectors_list(
    source_type: str | None,
    provider: str | None,
    enabled: bool | None,
    fmt: str,
) -> None:
    """List all registered connectors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        rows = (
            session.query(
                ConnectorRun.connector_name,
                ConnectorRun.source_type,
                ConnectorRun.provider,
                ConnectorRun.status,
            )
            .distinct(ConnectorRun.connector_name)
            .order_by(ConnectorRun.connector_name)
            .all()
        )

    if source_type:
        rows = [r for r in rows if r.source_type == source_type]
    if provider:
        rows = [r for r in rows if r.provider == provider]

    if not rows:
        console.print("[dim]No connectors found. Run the pipeline first.[/dim]")
        return

    if fmt == "json":
        data = [
            {
                "name": r.connector_name,
                "source_type": r.source_type,
                "provider": r.provider,
                "last_status": r.status,
            }
            for r in rows
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Connectors ({len(rows)})")
    table.add_column("Name", style="cyan")
    table.add_column("Source Type")
    table.add_column("Provider")
    table.add_column("Last Status")

    for r in rows:
        status_style = {
            "success": "green",
            "error": "red",
            "partial": "yellow",
            "running": "cyan",
        }.get(r.status, "dim")
        table.add_row(
            r.connector_name,
            r.source_type,
            r.provider,
            f"[{status_style}]{r.status}[/{status_style}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


@connectors.command("show")
@click.argument("name")
def connectors_show(name: str) -> None:
    """Show details for a specific connector."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        run = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.connector_name == name)
            .order_by(ConnectorRun.started_at.desc())
            .first()
        )

    if not run:
        _error(f"No connector found with name '{name}'. Run the pipeline first.")

    from rich.panel import Panel

    console.print(
        Panel(
            f"[bold]{run.connector_name}[/bold]\n\n"
            f"Source Type:  {run.source_type}\n"
            f"Provider:     {run.provider}\n"
            f"Last Status:  {run.status}\n"
            f"Last Run:     {run.started_at}\n"
            f"Events:       {run.event_count}\n"
            f"Errors:       {run.error_count}",
            title="[bold cyan]Connector[/bold cyan]",
            border_style="cyan",
        )
    )
    if run.errors:
        console.print("\n[yellow]Recent errors:[/yellow]")
        for err in (run.errors or [])[:5]:
            console.print(f"  [dim]- {err}[/dim]")


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------


@connectors.command("test")
@click.argument("name")
def connectors_test(name: str) -> None:
    """Run health_check() on a connector."""
    reg = _get_registry()
    connector = reg.get(name)
    if connector is None:
        console.print(
            f"[yellow]Connector '{name}' is not active in the registry. "
            "It must be instantiated via the pipeline first.[/yellow]"
        )
        return

    console.print(f"[dim]Testing connector {name}...[/dim]")
    try:
        ok = connector.health_check()
        if ok:
            console.print(f"[green]PASS[/green] {name} is reachable.")
        else:
            console.print(f"[red]FAIL[/red] {name} health check returned False.")
    except Exception as exc:
        console.print(f"[red]FAIL[/red] {name} raised: {exc}")


# ---------------------------------------------------------------------------
# test-all
# ---------------------------------------------------------------------------


@connectors.command("test-all")
def connectors_test_all() -> None:
    """Run health_check() on all active connectors."""
    reg = _get_registry()
    active = reg.list_active()
    if not active:
        console.print("[dim]No active connectors in registry.[/dim]")
        return

    passed = 0
    failed = 0
    for name in sorted(active):
        connector = reg.get(name)
        if connector is None:
            continue
        try:
            ok = connector.health_check()
            if ok:
                console.print(f"  [green]PASS[/green] {name}")
                passed += 1
            else:
                console.print(f"  [red]FAIL[/red] {name}")
                failed += 1
        except Exception as exc:
            console.print(f"  [red]FAIL[/red] {name}: {exc}")
            failed += 1

    console.print(f"\n[bold]Results: {passed} passed, {failed} failed[/bold]")


# ---------------------------------------------------------------------------
# enable / disable
# ---------------------------------------------------------------------------


@connectors.command("enable")
@click.argument("name")
def connectors_enable(name: str) -> None:
    """Enable a connector (sets config.enabled = True)."""
    reg = _get_registry()
    connector = reg.get(name)
    if connector is None:
        _error(f"Connector '{name}' not found in active registry.")
    connector.config.enabled = True  # type: ignore[union-attr]
    console.print(f"[green]Connector '{name}' enabled.[/green]")


@connectors.command("disable")
@click.argument("name")
def connectors_disable(name: str) -> None:
    """Disable a connector (sets config.enabled = False)."""
    reg = _get_registry()
    connector = reg.get(name)
    if connector is None:
        _error(f"Connector '{name}' not found in active registry.")
    connector.config.enabled = False  # type: ignore[union-attr]
    console.print(f"[yellow]Connector '{name}' disabled.[/yellow]")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@connectors.command("status")
@click.option("--limit", "-n", default=20, help="Number of recent runs to show")
def connectors_status(limit: int) -> None:
    """Show recent run status for all connectors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        rows = (
            session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(limit).all()
        )

    if not rows:
        console.print("[dim]No connector runs found.[/dim]")
        return

    table = Table(title="Recent Connector Runs")
    table.add_column("Name", style="cyan")
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Started At")

    for run in rows:
        status_style = {
            "success": "green",
            "error": "red",
            "partial": "yellow",
            "running": "cyan",
        }.get(run.status, "dim")
        dur = f"{run.duration_seconds:.1f}s" if run.duration_seconds else "\u2014"
        table.add_row(
            run.connector_name,
            f"[{status_style}]{run.status}[/{status_style}]",
            str(run.event_count or 0),
            str(run.error_count or 0),
            dur,
            str(run.started_at)[:19] if run.started_at else "\u2014",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------


@connectors.command("history")
@click.argument("name")
@click.option("--limit", "-n", default=10, help="Number of runs to show")
def connectors_history(name: str, limit: int) -> None:
    """Show run history for a specific connector."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        rows = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.connector_name == name)
            .order_by(ConnectorRun.started_at.desc())
            .limit(limit)
            .all()
        )

    if not rows:
        _error(f"No history found for connector '{name}'.")

    table = Table(title=f"History: {name}")
    table.add_column("Run ID", style="dim", max_width=8)
    table.add_column("Status")
    table.add_column("Events", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Duration", justify="right")
    table.add_column("Started At")

    for run in rows:
        status_style = {
            "success": "green",
            "error": "red",
            "partial": "yellow",
        }.get(run.status, "dim")
        dur = f"{run.duration_seconds:.1f}s" if run.duration_seconds else "\u2014"
        table.add_row(
            run.id[:8],
            f"[{status_style}]{run.status}[/{status_style}]",
            str(run.event_count or 0),
            str(run.error_count or 0),
            dur,
            str(run.started_at)[:19] if run.started_at else "\u2014",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------


@connectors.command("schema")
@click.argument("name")
def connectors_schema(name: str) -> None:
    """Show the raw event schema (event_types) produced by a connector."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent, ConnectorRun

    init_db()
    with get_session() as session:
        run = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.connector_name == name)
            .order_by(ConnectorRun.started_at.desc())
            .first()
        )
        if not run:
            _error(f"No runs found for connector '{name}'.")

        event_types = (
            session.query(RawEvent.event_type)
            .filter(RawEvent.connector_run_id == run.id)
            .distinct()
            .all()
        )

    types = sorted(set(r[0] for r in event_types))
    if not types:
        console.print("[dim]No events recorded for this connector.[/dim]")
        return

    console.print(f"[bold]Event types produced by '{name}':[/bold]")
    for et in types:
        console.print(f"  [cyan]{et}[/cyan]")


# ---------------------------------------------------------------------------
# validate / validate-all
# ---------------------------------------------------------------------------


@connectors.command("validate")
@click.argument("name")
def connectors_validate(name: str) -> None:
    """Validate connector configuration (check required fields)."""
    reg = _get_registry()
    connector = reg.get(name)
    if connector is None:
        console.print(
            f"[yellow]Connector '{name}' not in active registry. "
            "Cannot validate — run the pipeline to instantiate connectors.[/yellow]"
        )
        return

    errors = connector.validate()
    if not errors:
        console.print(f"[green]PASS[/green] Connector '{name}' configuration is valid.")
    else:
        console.print(f"[red]FAIL[/red] Connector '{name}' has {len(errors)} validation error(s):")
        for err in errors:
            console.print(f"  [red]- {err}[/red]")


@connectors.command("validate-all")
def connectors_validate_all() -> None:
    """Validate all active connector configurations."""
    reg = _get_registry()
    active = reg.list_active()
    if not active:
        console.print("[dim]No active connectors in registry.[/dim]")
        return

    all_ok = True
    for name in sorted(active):
        connector = reg.get(name)
        if connector is None:
            continue
        errors = connector.validate()
        if not errors:
            console.print(f"  [green]PASS[/green] {name}")
        else:
            all_ok = False
            console.print(f"  [red]FAIL[/red] {name}: {'; '.join(errors[:2])}")

    if all_ok:
        console.print("\n[green]All connectors valid.[/green]")
    else:
        console.print("\n[red]Some connectors have validation errors.[/red]")


# ---------------------------------------------------------------------------
# credentials / credentials-check
# ---------------------------------------------------------------------------


@connectors.command("credentials")
@click.argument("name")
def connectors_credentials(name: str) -> None:
    """Show which env vars a connector requires (never shows values)."""
    reg = _get_registry()
    connector = reg.get(name)
    if connector is None:
        _error(
            f"Connector '{name}' not in active registry. "
            "Run the pipeline first to instantiate connectors."
        )

    secret_vars = connector.config.secret_env_vars  # type: ignore[union-attr]
    if not secret_vars:
        console.print(f"[dim]Connector '{name}' has no declared credential env vars.[/dim]")
        return

    console.print(f"[bold]Required credentials for '{name}':[/bold]")
    for var in secret_vars:
        is_set = bool(os.environ.get(var))
        status = "[green]set[/green]" if is_set else "[red]MISSING[/red]"
        console.print(f"  {var:<40} {status}")


@connectors.command("credentials-check")
def connectors_credentials_check() -> None:
    """Check credential env vars for all active connectors."""
    reg = _get_registry()
    active = reg.list_active()
    if not active:
        console.print("[dim]No active connectors.[/dim]")
        return

    missing_count = 0
    for name in sorted(active):
        connector = reg.get(name)
        if connector is None:
            continue
        missing = [v for v in connector.config.secret_env_vars if not os.environ.get(v)]
        if missing:
            missing_count += 1
            console.print(f"  [red]MISSING[/red] {name}: {', '.join(missing)}")

    if missing_count == 0:
        console.print("[green]All connector credentials are set.[/green]")
    else:
        console.print(f"\n[red]{missing_count} connector(s) have missing credentials.[/red]")


# ---------------------------------------------------------------------------
# collect / collect-all
# ---------------------------------------------------------------------------


@connectors.command("collect")
@click.argument("name")
def connectors_collect(name: str) -> None:
    """Run a single connector's collect() method."""
    reg = _get_registry()
    connector = reg.get(name)
    if connector is None:
        _error(
            f"Connector '{name}' not in active registry. "
            "Run 'warlock collect' first to initialize connectors."
        )

    if not connector.config.enabled:
        _error(f"Connector '{name}' is disabled. Enable it first.")

    console.print(f"[dim]Collecting from {name}...[/dim]")
    try:
        result = connector.collect()
        status_style = {"success": "green", "partial": "yellow", "error": "red"}.get(
            result.status, "dim"
        )
        console.print(f"[{status_style}]{result.status.upper()}[/{status_style}] ", end="")
        console.print(
            f"{name}: {result.event_count} event(s) collected in {result.duration_seconds:.1f}s"
            if result.duration_seconds
            else f"{name}: {result.event_count} event(s)"
        )
        if result.errors:
            console.print(f"[yellow]{len(result.errors)} error(s):[/yellow]")
            for err in result.errors[:3]:
                console.print(f"  [dim]- {err}[/dim]")
    except Exception as exc:
        console.print(f"[red]ERROR[/red] {name}: {exc}")


@connectors.command("collect-all")
@click.option("--max-workers", default=None, type=int, help="Thread pool size")
def connectors_collect_all(max_workers: int | None) -> None:
    """Run collect() on all enabled active connectors."""
    reg = _get_registry()
    results = reg.collect_all(max_workers=max_workers)

    if not results:
        console.print("[dim]No active connectors to collect from.[/dim]")
        return

    succeeded = sum(1 for r in results if r.status == "success")
    failed = sum(1 for r in results if r.status == "error")
    partial = sum(1 for r in results if r.status == "partial")
    total_events = sum(r.event_count for r in results)

    console.print(
        f"[bold]Collected {total_events} events from {len(results)} connectors. "
        f"Success: {succeeded}, Partial: {partial}, Error: {failed}[/bold]"
    )

    for r in results:
        if r.status != "success":
            console.print(f"  [yellow]{r.connector_name}:[/yellow] {r.status}")
            for err in r.errors[:2]:
                console.print(f"    [dim]- {err}[/dim]")


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@connectors.command("stats")
def connectors_stats() -> None:
    """Aggregate connector statistics by source_type."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        rows = session.query(
            ConnectorRun.source_type,
            ConnectorRun.status,
            ConnectorRun.event_count,
            ConnectorRun.error_count,
        ).all()

    if not rows:
        console.print("[dim]No connector run data found.[/dim]")
        return

    by_type: dict[str, dict] = defaultdict(
        lambda: {"runs": 0, "success": 0, "error": 0, "events": 0}
    )
    for r in rows:
        st = r.source_type or "unknown"
        by_type[st]["runs"] += 1
        by_type[st]["events"] += r.event_count or 0
        if r.status == "success":
            by_type[st]["success"] += 1
        elif r.status == "error":
            by_type[st]["error"] += 1

    table = Table(title="Connector Stats by Source Type")
    table.add_column("Source Type", style="cyan")
    table.add_column("Runs", justify="right")
    table.add_column("Success", justify="right")
    table.add_column("Error", justify="right")
    table.add_column("Total Events", justify="right")

    for st in sorted(by_type):
        d = by_type[st]
        table.add_row(
            st,
            str(d["runs"]),
            f"[green]{d['success']}[/green]",
            f"[red]{d['error']}[/red]" if d["error"] else "0",
            str(d["events"]),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# event-types
# ---------------------------------------------------------------------------


@connectors.command("event-types")
@click.option("--source-type", "-t", default=None, help="Filter by source type")
def connectors_event_types(source_type: str | None) -> None:
    """List all event_types across all connectors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import RawEvent

    init_db()
    with get_session() as session:
        q = session.query(
            RawEvent.event_type,
            RawEvent.source_type,
            RawEvent.provider,
        ).distinct()
        if source_type:
            q = q.filter(RawEvent.source_type == source_type)
        rows = q.order_by(RawEvent.source_type, RawEvent.event_type).all()

    if not rows:
        console.print("[dim]No event types found.[/dim]")
        return

    table = Table(title=f"Event Types ({len(rows)})")
    table.add_column("Event Type", style="cyan")
    table.add_column("Source Type")
    table.add_column("Provider")

    for r in rows:
        table.add_row(r.event_type, r.source_type, r.provider)

    console.print(table)


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------


@connectors.command("compare")
@click.argument("name_a")
@click.argument("name_b")
def connectors_compare(name_a: str, name_b: str) -> None:
    """Compare event counts and source types for two connectors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:

        def _stats(name: str) -> dict:
            run = (
                session.query(ConnectorRun)
                .filter(ConnectorRun.connector_name == name)
                .order_by(ConnectorRun.started_at.desc())
                .first()
            )
            if not run:
                return {}
            return {
                "source_type": run.source_type,
                "provider": run.provider,
                "status": run.status,
                "event_count": run.event_count,
                "error_count": run.error_count,
                "started_at": str(run.started_at)[:19],
            }

        a = _stats(name_a)
        b = _stats(name_b)

    if not a:
        _error(f"No data found for connector '{name_a}'.")
    if not b:
        _error(f"No data found for connector '{name_b}'.")

    table = Table(title="Connector Comparison")
    table.add_column("Metric", style="cyan")
    table.add_column(name_a)
    table.add_column(name_b)

    for key in ("source_type", "provider", "status", "event_count", "error_count", "started_at"):
        table.add_row(
            key.replace("_", " ").title(), str(a.get(key, "\u2014")), str(b.get(key, "\u2014"))
        )

    console.print(table)


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


@connectors.command("export")
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
@click.option("--source-type", "-t", default=None, help="Filter by source type")
def connectors_export(output: str | None, source_type: str | None) -> None:
    """Export connector run history to JSON."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        q = session.query(ConnectorRun).order_by(
            ConnectorRun.connector_name, ConnectorRun.started_at.desc()
        )
        if source_type:
            q = q.filter(ConnectorRun.source_type == source_type)
        rows = q.all()

    data = [
        {
            "id": r.id,
            "connector_name": r.connector_name,
            "source": r.source,
            "source_type": r.source_type,
            "provider": r.provider,
            "status": r.status,
            "event_count": r.event_count,
            "error_count": r.error_count,
            "started_at": str(r.started_at),
            "completed_at": str(r.completed_at) if r.completed_at else None,
            "duration_seconds": r.duration_seconds,
        }
        for r in rows
    ]

    payload = json.dumps(data, indent=2)
    if output:
        with open(output, "w") as fh:
            fh.write(payload)
        console.print(f"[green]Exported {len(data)} runs to {output}[/green]")
    else:
        console.print(payload)


# ---------------------------------------------------------------------------
# import (placeholder — prints helpful message)
# ---------------------------------------------------------------------------


@connectors.command("import")
@click.argument("file")
def connectors_import(file: str) -> None:
    """Import connector configurations from a JSON file (metadata only)."""
    import pathlib

    path = pathlib.Path(file)
    if not path.exists():
        _error(f"File not found: {file}")

    try:
        with open(path) as fh:
            configs = json.load(fh)
    except json.JSONDecodeError as exc:
        _error(f"Invalid JSON: {exc}")

    if not isinstance(configs, list):
        _error("Expected a JSON array of connector config objects.")

    console.print(f"[dim]Parsed {len(configs)} connector config(s) from {file}.[/dim]")
    console.print(
        "[yellow]Note: This command validates and displays configs. "
        "To activate connectors, wire them into your pipeline.[/yellow]"
    )
    for cfg in configs[:5]:
        name = cfg.get("name", "?")
        stype = cfg.get("source_type", "?")
        provider = cfg.get("provider", "?")
        console.print(f"  [cyan]{name}[/cyan]  {stype} / {provider}")
    if len(configs) > 5:
        console.print(f"  [dim]... and {len(configs) - 5} more[/dim]")


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------


@connectors.command("health")
def connectors_health() -> None:
    """Show an overall health summary of all connectors."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        # Most recent run per connector
        from sqlalchemy import func

        subq = (
            session.query(
                ConnectorRun.connector_name,
                func.max(ConnectorRun.started_at).label("latest"),
            )
            .group_by(ConnectorRun.connector_name)
            .subquery()
        )
        rows = (
            session.query(ConnectorRun)
            .join(
                subq,
                (ConnectorRun.connector_name == subq.c.connector_name)
                & (ConnectorRun.started_at == subq.c.latest),
            )
            .all()
        )

    if not rows:
        console.print("[dim]No connector data found.[/dim]")
        return

    status_counts: Counter[str] = Counter(r.status for r in rows)
    console.print(f"\n[bold]Connector Health Summary ({len(rows)} connectors)[/bold]")
    console.print(f"  [green]Success :[/green]  {status_counts.get('success', 0)}")
    console.print(f"  [yellow]Partial :[/yellow]  {status_counts.get('partial', 0)}")
    console.print(f"  [red]Error   :[/red]  {status_counts.get('error', 0)}")
    console.print(f"  [cyan]Running :[/cyan]  {status_counts.get('running', 0)}")
    error_rows = [r for r in rows if r.status == "error"]
    if error_rows:
        console.print("\n[red]Connectors in error state:[/red]")
        for r in error_rows[:10]:
            console.print(f"  [dim]{r.connector_name}[/dim] (last run: {str(r.started_at)[:19]})")


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------


@connectors.command("schedule")
@click.option("--source-type", "-t", default=None, help="Filter by source type")
def connectors_schedule(source_type: str | None) -> None:
    """Show poll intervals for active connectors."""
    reg = _get_registry()
    active = reg.list_active()
    if not active:
        console.print("[dim]No active connectors in registry.[/dim]")
        return

    table = Table(title="Connector Schedule")
    table.add_column("Name", style="cyan")
    table.add_column("Source Type")
    table.add_column("Poll Interval (min)", justify="right")
    table.add_column("Timeout (s)", justify="right")
    table.add_column("Enabled")

    for name in sorted(active):
        connector = reg.get(name)
        if connector is None:
            continue
        if source_type and connector.source_type.value != source_type:
            continue
        enabled = "[green]yes[/green]" if connector.config.enabled else "[red]no[/red]"
        table.add_row(
            name,
            connector.source_type.value,
            str(connector.config.poll_interval_minutes),
            str(connector.config.timeout_seconds),
            enabled,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


@connectors.command("errors")
@click.option("--limit", "-n", default=20, help="Max runs to show")
@click.option("--name", default=None, help="Filter by connector name")
def connectors_errors(limit: int, name: str | None) -> None:
    """Show connectors with errors from recent runs."""
    from warlock.db.engine import get_session, init_db
    from warlock.db.models import ConnectorRun

    init_db()
    with get_session() as session:
        q = (
            session.query(ConnectorRun)
            .filter(ConnectorRun.error_count > 0)
            .order_by(ConnectorRun.started_at.desc())
        )
        if name:
            q = q.filter(ConnectorRun.connector_name == name)
        rows = q.limit(limit).all()

    if not rows:
        console.print("[green]No connector errors found.[/green]")
        return

    table = Table(title="Connector Errors")
    table.add_column("Name", style="cyan")
    table.add_column("Status")
    table.add_column("Error Count", justify="right")
    table.add_column("Started At")
    table.add_column("First Error", max_width=60)

    for run in rows:
        first_err = (run.errors or [None])[0] or "\u2014"
        table.add_row(
            run.connector_name,
            run.status,
            str(run.error_count),
            str(run.started_at)[:19],
            str(first_err)[:60],
        )

    console.print(table)
