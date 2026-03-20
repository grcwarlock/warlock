"""Pipeline status and connector health dashboard.

Shows the last pipeline run stats, connector health for all 40 connectors,
run history, a live log view, and a button to trigger a new collection run.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    RichLog,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fmt_time(dt: datetime | None) -> str:
    """Format a datetime for display, or return '--' if None."""
    if dt is None:
        return "--"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_duration(seconds: float | None) -> str:
    if seconds is None:
        return "--"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.0f}s"


def _status_markup(status: str) -> str:
    """Return Rich markup for a connector status string."""
    s = status.lower()
    if s in ("success", "up", "active", "healthy"):
        return f"[green bold]{status}[/]"
    if s in ("error", "failed", "down"):
        return f"[red bold]{status}[/]"
    if s in ("disabled", "skipped"):
        return f"[dim]{status}[/]"
    if s in ("running", "partial"):
        return f"[yellow]{status}[/]"
    return status


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

PIPELINE_SCREEN_CSS = """\
#pipeline-screen {
    layout: vertical;
}

#top-bar {
    height: 3;
    padding: 0 2;
    content-align: right middle;
}

#status-panel {
    height: auto;
    max-height: 10;
    padding: 1 2;
    border: solid $accent;
    margin: 0 1;
}

#connector-table {
    height: 1fr;
    min-height: 12;
    margin: 0 1;
}

#history-panel {
    height: auto;
    max-height: 14;
    padding: 0 1;
}

#history-table {
    height: auto;
    max-height: 12;
}

#log-panel {
    height: 12;
    border: solid $accent;
    margin: 0 1;
}

#no-data-label {
    text-align: center;
    padding: 4;
    color: $text-muted;
}
"""


# ---------------------------------------------------------------------------
# Screen
# ---------------------------------------------------------------------------


class PipelineScreen(Screen):
    """Pipeline operations and connector health view."""

    CSS = PIPELINE_SCREEN_CSS
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
        ("r", "refresh_data", "Refresh"),
        ("p", "run_pipeline", "Run Pipeline"),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._pipeline_running = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="pipeline-screen"):
            with Horizontal(id="top-bar"):
                yield Button(
                    "Run Pipeline",
                    variant="warning",
                    id="run-pipeline-btn",
                )
                yield Button("Refresh", variant="default", id="refresh-btn")

            # Status summary of the last run
            yield Container(
                Label("", id="status-summary"),
                id="status-panel",
            )

            # Connector health table
            with VerticalScroll():
                yield DataTable(id="connector-table")

            # Pipeline run history
            with Container(id="history-panel"):
                yield Label("[bold]Pipeline History[/bold]  (last 10 runs)")
                yield DataTable(id="history-table")

            # Live log
            yield RichLog(id="log-panel", wrap=True, highlight=True, markup=True)

            yield Label(
                "No pipeline data. Run 'warlock collect' or demo seed first.",
                id="no-data-label",
            )
        yield Footer()

    def on_mount(self) -> None:
        # Set up connector table columns
        ct = self.query_one("#connector-table", DataTable)
        ct.add_columns("Connector", "Type", "Provider", "Status", "Last Run", "Events")

        # History table columns
        ht = self.query_one("#history-table", DataTable)
        ht.add_columns("Run ID", "Started", "Duration", "Events", "Findings", "Status")

        self.query_one("#log-panel").display = False
        self._load_data()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-pipeline-btn":
            self.action_run_pipeline()
        elif event.button.id == "refresh-btn":
            self.action_refresh_data()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_refresh_data(self) -> None:
        self._load_data()

    def action_run_pipeline(self) -> None:
        if self._pipeline_running:
            self.notify("Pipeline is already running.", severity="warning")
            return
        # Show confirmation since this calls real APIs
        self.notify(
            "Starting pipeline collection. This calls live connector APIs.",
            severity="warning",
        )
        self._run_pipeline_worker()

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def _load_data(self) -> None:
        """Load connector runs and pipeline history from the DB."""
        try:
            from warlock.db.engine import get_session

            session_gen = get_session()
            session = next(session_gen)
            try:
                self._populate_connectors(session)
                self._populate_history(session)
                self._populate_status(session)
            finally:
                try:
                    next(session_gen)
                except StopIteration:
                    pass
        except Exception:
            log.debug("Failed to load pipeline data", exc_info=True)
            self.query_one("#no-data-label").display = True
            return

    def _populate_status(self, session: Any) -> None:
        """Show summary stats for the latest pipeline run."""

        from warlock.db.models import ConnectorRun

        # Find the most recent connector run batch (same started_at minute)
        latest = session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).first()
        if not latest:
            self.query_one("#status-panel").display = False
            self.query_one("#no-data-label").display = True
            return

        self.query_one("#no-data-label").display = False

        # Count totals for runs that share the same approximate start time
        # (within a 5 minute window of the latest run)
        all_runs = (
            session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(50).all()
        )

        # Group by proximity to the latest run
        latest_batch: list[Any] = []
        if latest.started_at:
            for run in all_runs:
                if (
                    run.started_at
                    and abs((run.started_at - latest.started_at).total_seconds()) < 300
                ):
                    latest_batch.append(run)

        if not latest_batch:
            latest_batch = [latest]

        total_events = sum(r.event_count or 0 for r in latest_batch)
        succeeded = sum(1 for r in latest_batch if r.status == "success")
        failed = sum(1 for r in latest_batch if r.status == "error")
        duration = latest.duration_seconds

        summary = (
            f"[bold]Last Pipeline Run[/bold]\n"
            f"  Started: {_fmt_time(latest.started_at)}  |  "
            f"Duration: {_fmt_duration(duration)}  |  "
            f"Events: [bold]{total_events:,}[/]\n"
            f"  Connectors: [green]{succeeded} succeeded[/]  "
            f"[red]{failed} failed[/]  "
            f"({len(latest_batch)} total)"
        )
        self.query_one("#status-summary", Label).update(summary)
        self.query_one("#status-panel").display = True

    def _populate_connectors(self, session: Any) -> None:
        """Fill the connector health table with the latest run per connector."""
        from sqlalchemy import func

        from warlock.db.models import ConnectorRun

        # Get the most recent run for each connector
        subq = (
            session.query(
                ConnectorRun.connector_name,
                func.max(ConnectorRun.started_at).label("max_start"),
            )
            .group_by(ConnectorRun.connector_name)
            .subquery()
        )

        latest_runs = (
            session.query(ConnectorRun)
            .join(
                subq,
                (ConnectorRun.connector_name == subq.c.connector_name)
                & (ConnectorRun.started_at == subq.c.max_start),
            )
            .order_by(ConnectorRun.connector_name)
            .all()
        )

        table = self.query_one("#connector-table", DataTable)
        table.clear()

        if not latest_runs:
            return

        for run in latest_runs:
            table.add_row(
                run.connector_name,
                run.source_type or "--",
                run.provider or "--",
                _status_markup(run.status or "unknown"),
                _fmt_time(run.completed_at or run.started_at),
                str(run.event_count or 0),
            )

    def _populate_history(self, session: Any) -> None:
        """Show the last 10 pipeline runs (distinct batches)."""
        from warlock.db.models import ConnectorRun

        # Get last 10 distinct run batches by grouping on started_at
        # For simplicity, grab last 10 connector runs and deduplicate
        runs = session.query(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(200).all()

        table = self.query_one("#history-table", DataTable)
        table.clear()

        if not runs:
            self.query_one("#history-panel").display = False
            return

        self.query_one("#history-panel").display = True

        # Group into batches by 5-minute windows
        batches: list[list[Any]] = []
        current_batch: list[Any] = []
        anchor: datetime | None = None

        for run in runs:
            if not run.started_at:
                continue
            if anchor is None or abs((run.started_at - anchor).total_seconds()) < 300:
                if anchor is None:
                    anchor = run.started_at
                current_batch.append(run)
            else:
                if current_batch:
                    batches.append(current_batch)
                current_batch = [run]
                anchor = run.started_at
            if len(batches) >= 10:
                break

        if current_batch and len(batches) < 10:
            batches.append(current_batch)

        for batch in batches[:10]:
            first = batch[0]
            total_events = sum(r.event_count or 0 for r in batch)
            any_failed = any(r.status == "error" for r in batch)
            status = "[red]FAILED[/]" if any_failed else "[green]OK[/]"
            run_id = first.id[:8] if first.id else "--"

            table.add_row(
                run_id,
                _fmt_time(first.started_at),
                _fmt_duration(first.duration_seconds),
                str(total_events),
                str(len(batch)),
                status,
            )

    # ------------------------------------------------------------------
    # Pipeline execution worker
    # ------------------------------------------------------------------

    @work(thread=True, exclusive=True, group="pipeline-run")
    def _run_pipeline_worker(self) -> None:
        """Execute the pipeline in a background thread with live logging."""
        self._pipeline_running = True
        rich_log = self.query_one("#log-panel", RichLog)
        self.call_from_thread(self._show_log_panel, True)

        def _log_line(msg: str) -> None:
            self.call_from_thread(rich_log.write, msg)

        try:
            _log_line("[bold]Starting pipeline collection...[/]")

            from warlock.db.engine import get_session, init_db
            from warlock.pipeline.orchestrator import Pipeline

            init_db()
            session_gen = get_session()
            session = next(session_gen)

            try:
                pipeline = Pipeline(session=session)

                # Hook into the event bus for live logging if possible
                try:
                    bus = pipeline.bus if hasattr(pipeline, "bus") else None
                    if bus and hasattr(bus, "subscribe"):

                        def _on_event(event: Any) -> None:
                            _log_line(f"  {event}")

                        bus.subscribe(_on_event)
                except Exception:
                    pass

                _log_line("Running connectors...")
                stats = pipeline.run()

                _log_line("\n[bold green]Pipeline complete.[/]")
                _log_line(f"  Connectors succeeded: {stats.connectors_succeeded}")
                _log_line(f"  Connectors failed:    {stats.connectors_failed}")
                _log_line(f"  Raw events:           {stats.raw_events_collected}")
                _log_line(f"  Findings normalized:  {stats.findings_normalized}")
                _log_line(f"  Controls mapped:      {stats.controls_mapped:,}")
                _log_line(f"  Results assessed:     {stats.results_assessed:,}")

                if stats.errors:
                    _log_line("\n[red]Errors:[/]")
                    for err in stats.errors[:20]:
                        _log_line(f"  - {err}")

                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                try:
                    next(session_gen)
                except StopIteration:
                    pass

            # Refresh the tables
            self.call_from_thread(self._load_data)

        except Exception as exc:
            log.exception("Pipeline run failed")
            _log_line(f"\n[red bold]Pipeline failed: {exc}[/]")
            self.call_from_thread(self.notify, f"Pipeline failed: {exc}", severity="error")
        finally:
            self._pipeline_running = False

    def _show_log_panel(self, visible: bool) -> None:
        self.query_one("#log-panel").display = visible
