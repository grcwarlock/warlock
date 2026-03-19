"""Periodic pipeline scheduler for continuous monitoring.

Supports multiple independent schedules (pipeline collection, posture snapshots,
cadence checks, retention purge) each running at their own interval.
Uses stdlib ``threading`` for background execution.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schedule definitions
# ---------------------------------------------------------------------------

DEFAULT_SCHEDULES: dict[str, dict[str, Any]] = {
    "pipeline_collect": {"interval_minutes": 60, "enabled": True},
    "posture_snapshot": {"interval_minutes": 1440, "enabled": True},   # daily
    "cadence_check": {"interval_minutes": 60, "enabled": True},        # after each collect
    "retention_purge": {"interval_minutes": 10080, "enabled": True},  # weekly
}


@dataclass
class ScheduleState:
    """Tracks per-schedule execution state."""
    name: str
    interval_seconds: float
    enabled: bool
    last_run: datetime | None = None
    run_count: int = 0
    last_error: str | None = None


# ---------------------------------------------------------------------------
# PipelineScheduler
# ---------------------------------------------------------------------------


class PipelineScheduler:
    """Multi-schedule pipeline scheduler running in a background thread.

    Each schedule runs independently at its own interval. The main loop
    ticks every second and dispatches any schedule that is due.
    """

    def __init__(self, interval_minutes: int = 60):
        """Initialize scheduler.

        Args:
            interval_minutes: Default interval for pipeline_collect.
                Other schedules use their DEFAULT_SCHEDULES intervals.
        """
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Build schedule states
        self._schedules: dict[str, ScheduleState] = {}
        for name, config in DEFAULT_SCHEDULES.items():
            interval = config["interval_minutes"]
            if name == "pipeline_collect":
                interval = interval_minutes
            self._schedules[name] = ScheduleState(
                name=name,
                interval_seconds=interval * 60,
                enabled=config["enabled"],
            )

    def start(self) -> None:
        """Start the scheduler in a background daemon thread."""
        with self._lock:
            if self._running:
                log.warning("Scheduler already running")
                return
            self._running = True
            self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run_loop,
            name="warlock-scheduler",
            daemon=True,
        )
        self._thread.start()
        log.info("Scheduler started with %d schedules", len(self._schedules))

    def stop(self) -> None:
        """Stop the scheduler gracefully."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        self._thread = None
        log.info("Scheduler stopped")

    def _run_loop(self) -> None:
        """Main loop: check all schedules, dispatch any that are due."""
        # Run all enabled schedules on startup
        for name, sched in self._schedules.items():
            if sched.enabled:
                self._dispatch(name)

        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)

            for name, sched in self._schedules.items():
                if not sched.enabled:
                    continue
                if sched.last_run is None:
                    continue

                elapsed = (now - sched.last_run).total_seconds()
                if elapsed >= sched.interval_seconds:
                    self._dispatch(name)

            # Sleep 1 second between ticks for responsive stop
            self._stop_event.wait(timeout=1.0)

            with self._lock:
                if not self._running:
                    break

    def _dispatch(self, schedule_name: str) -> None:
        """Execute the handler for a schedule."""
        handlers: dict[str, Callable[[], None]] = {
            "pipeline_collect": self._execute_collect,
            "posture_snapshot": self._execute_snapshot,
            "cadence_check": self._execute_cadence,
            "retention_purge": self._execute_retention,
        }

        handler = handlers.get(schedule_name)
        if not handler:
            log.warning("No handler for schedule: %s", schedule_name)
            return

        sched = self._schedules[schedule_name]
        try:
            handler()
            with self._lock:
                sched.run_count += 1
                sched.last_run = datetime.now(timezone.utc)
                sched.last_error = None
            log.info("Schedule '%s' run #%d complete", schedule_name, sched.run_count)
        except Exception as exc:
            with self._lock:
                sched.run_count += 1
                sched.last_run = datetime.now(timezone.utc)
                sched.last_error = str(exc)
            log.exception("Schedule '%s' failed", schedule_name)

    def _execute_collect(self) -> None:
        """Run the 4-stage pipeline."""
        from warlock.db.engine import get_session, init_db
        from warlock.pipeline.bus import EventBus
        from warlock.pipeline.loader import build_pipeline

        init_db()
        bus = EventBus()
        pipeline = build_pipeline(bus)

        with get_session() as session:
            stats = pipeline.run(session)

        log.info(
            "Pipeline: %d events, %d findings, %d results",
            stats.raw_events_collected,
            stats.findings_normalized,
            stats.results_assessed,
        )

    def _execute_snapshot(self) -> None:
        """Take posture snapshots for all frameworks."""
        from warlock.db.engine import get_session, init_db
        from warlock.assessors.posture import PostureAggregator

        init_db()
        aggregator = PostureAggregator()

        with get_session() as session:
            snapshots = aggregator.take_snapshot(session)

        log.info("Posture snapshot: %d control snapshots created", len(snapshots))

    def _execute_cadence(self) -> None:
        """Check monitoring cadence and log stale controls."""
        from warlock.db.engine import get_session, init_db
        from warlock.assessors.cadence import CadenceChecker

        init_db()
        checker = CadenceChecker()

        with get_session() as session:
            stale = checker.get_stale_controls(session)

        if stale:
            log.warning(
                "Cadence check: %d stale controls (worst: %s %s at %.1fx overdue)",
                len(stale),
                stale[0].framework,
                stale[0].control_id,
                stale[0].staleness_ratio,
            )
        else:
            log.info("Cadence check: all controls within monitoring frequency")

    def _execute_retention(self) -> None:
        """Purge expired data respecting legal holds."""
        from warlock.db.engine import get_session, init_db
        from warlock.workflows.retention import RetentionManager

        init_db()
        manager = RetentionManager()

        with get_session() as session:
            result = manager.purge_expired(session, dry_run=False)

        purged = result.get("purged", 0)
        held = result.get("held_by_legal_hold", 0)
        if purged or held:
            log.info(
                "Retention purge: %d records purged, %d held by legal hold",
                purged, held,
            )
        else:
            log.info("Retention purge: nothing to purge")

    @property
    def status(self) -> dict[str, Any]:
        """Return scheduler status with per-schedule details."""
        with self._lock:
            schedules = {}
            for name, sched in self._schedules.items():
                next_run = None
                if self._running and sched.enabled and sched.last_run:
                    from datetime import timedelta
                    next_run = (
                        sched.last_run + timedelta(seconds=sched.interval_seconds)
                    ).isoformat()
                elif self._running and sched.enabled:
                    next_run = "imminent"

                schedules[name] = {
                    "enabled": sched.enabled,
                    "interval_minutes": int(sched.interval_seconds / 60),
                    "last_run": sched.last_run.isoformat() if sched.last_run else None,
                    "next_run": next_run,
                    "run_count": sched.run_count,
                    "last_error": sched.last_error,
                }

            return {
                "running": self._running,
                "schedules": schedules,
                # Backward compatibility
                "interval_minutes": int(
                    self._schedules["pipeline_collect"].interval_seconds / 60
                ),
                "last_run": schedules["pipeline_collect"]["last_run"],
                "next_run": schedules["pipeline_collect"]["next_run"],
                "run_count": self._schedules["pipeline_collect"].run_count,
                "last_error": self._schedules["pipeline_collect"].last_error,
            }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_scheduler: PipelineScheduler | None = None
_scheduler_lock = threading.Lock()


def get_scheduler(interval_minutes: int = 60) -> PipelineScheduler:
    """Get or create the global scheduler singleton."""
    global _scheduler
    with _scheduler_lock:
        if _scheduler is None:
            _scheduler = PipelineScheduler(interval_minutes=interval_minutes)
        return _scheduler
