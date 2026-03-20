"""Periodic pipeline scheduler for continuous monitoring.

Supports multiple independent schedules (pipeline collection, posture snapshots,
cadence checks, retention purge) each running at their own interval.
Uses stdlib ``threading`` for background execution.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
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
    "ccm_stale_check": {"interval_minutes": 60, "enabled": True},     # CCM stale control scan
    "risk_reeval_check": {"interval_minutes": 360, "enabled": True},  # risk acceptance re-eval (6h)
    # Monte Carlo pre-computation cache warm (opt-in, weekly by default)
    "risk_cache_precompute": {"interval_minutes": 10080, "enabled": False},
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
    # #38: track the in-flight Future so we can detect overlapping runs
    _future: Future | None = field(default=None, repr=False, compare=False)


# ---------------------------------------------------------------------------
# PipelineScheduler
# ---------------------------------------------------------------------------


class PipelineScheduler:
    """Multi-schedule pipeline scheduler running in a background thread.

    Each schedule runs independently at its own interval. The main loop
    ticks every second and dispatches any schedule that is due.
    """

    # #38: maximum concurrent schedule workers
    _POOL_SIZE = 4

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
        # #38: thread pool so schedule handlers don't block the main loop
        self._pool: ThreadPoolExecutor | None = None

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

        # Honour opt-in config flag for risk cache pre-computation
        try:
            from warlock.config import get_settings
            settings = get_settings()
            precompute_enabled = getattr(settings, "risk_cache_precompute_enabled", False)
            self._schedules["risk_cache_precompute"].enabled = precompute_enabled
        except Exception:  # pragma: no cover
            pass  # Config not available (tests, etc.) — keep default disabled

    def start(self) -> None:
        """Start the scheduler in a background daemon thread."""
        with self._lock:
            if self._running:
                log.warning("Scheduler already running")
                return
            self._running = True
            self._stop_event.clear()
            # #38: create worker pool alongside the scheduler thread
            self._pool = ThreadPoolExecutor(
                max_workers=self._POOL_SIZE,
                thread_name_prefix="warlock-sched-worker",
            )

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
        # #38: shut down the pool after the scheduler loop exits
        if self._pool is not None:
            self._pool.shutdown(wait=False)
            self._pool = None
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
        """Submit the handler for a schedule to the worker pool.

        If the previous run of this schedule is still in flight, the dispatch
        is skipped to prevent overlapping executions of the same schedule.
        """
        handlers: dict[str, Callable[[], None]] = {
            "pipeline_collect": self._execute_collect,
            "posture_snapshot": self._execute_snapshot,
            "cadence_check": self._execute_cadence,
            "retention_purge": self._execute_retention,
            "ccm_stale_check": self._execute_ccm_stale,
            "risk_reeval_check": self._execute_risk_reeval,
            "risk_cache_precompute": self._execute_risk_cache_precompute,
        }

        handler = handlers.get(schedule_name)
        if not handler:
            log.warning("No handler for schedule: %s", schedule_name)
            return

        sched = self._schedules[schedule_name]

        # #38: prevent overlapping executions of the same schedule
        with self._lock:
            if sched._future is not None and not sched._future.done():
                log.warning(
                    "Schedule '%s' still running — skipping overlap", schedule_name
                )
                return
            pool = self._pool

        if pool is None:
            # Pool not available (scheduler stopped); run inline as fallback
            self._run_handler(schedule_name, handler, sched)
            return

        def _worker():
            self._run_handler(schedule_name, handler, sched)

        with self._lock:
            sched._future = pool.submit(_worker)

    def _run_handler(
        self,
        schedule_name: str,
        handler: Callable[[], None],
        sched: ScheduleState,
    ) -> None:
        """Execute a schedule handler and record the outcome."""
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
        from warlock.pipeline.queue import create_bus_from_settings
        from warlock.pipeline.loader import build_pipeline

        init_db()
        bus = create_bus_from_settings()
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

    def _execute_ccm_stale(self) -> None:
        """Scan for controls that have not been assessed within their monitoring frequency."""
        from warlock.config import get_settings
        from warlock.db.engine import get_session, init_db
        from warlock.pipeline.ccm import ContinuousControlMonitor
        from warlock.pipeline.loader import build_pipeline

        settings = get_settings()
        if not settings.ccm_enabled:
            log.debug("CCM stale check skipped — ccm_enabled=False")
            return

        init_db()
        from warlock.pipeline.queue import create_bus_from_settings

        bus = create_bus_from_settings()
        pipeline = build_pipeline(bus)

        monitor = ContinuousControlMonitor(
            assessor=pipeline.assessor,
            mapper=pipeline.mapper,
            bus=bus,
        )

        with get_session() as session:
            monitor.build_control_evidence_map(session)
            stale = monitor.check_stale_controls(
                session,
                max_age_hours=settings.ccm_stale_threshold_hours,
            )

        if stale:
            log.warning(
                "CCM stale check: %d control(s) overdue for reassessment",
                len(stale),
            )
        else:
            log.info("CCM stale check: all controls current")

    def _execute_risk_reeval(self) -> None:
        """Check active risk acceptances for re-evaluation triggers."""
        from warlock.db.engine import get_session, init_db
        from warlock.workflows.risk_acceptance import RiskAcceptanceManager

        init_db()
        manager = RiskAcceptanceManager()

        with get_session() as session:
            triggered = manager.evaluate_triggers(session)

        if triggered:
            log.warning(
                "Risk re-evaluation check: %d acceptance(s) triggered for review",
                len(triggered),
            )
        else:
            log.info("Risk re-evaluation check: no acceptances triggered")

    def _execute_risk_cache_precompute(self) -> None:
        """Pre-warm the Monte Carlo risk cache for all active frameworks."""
        from warlock.config import get_settings
        from warlock.db.engine import get_session, init_db
        from warlock.assessors.risk_engine import RiskEngine

        settings = get_settings()
        if not getattr(settings, "risk_cache_precompute_enabled", False):
            log.debug("risk_cache_precompute skipped — risk_cache_precompute_enabled=False")
            return

        init_db()
        engine = RiskEngine()

        with get_session() as session:
            summary = engine.precompute_all_frameworks(session)

        hits = sum(1 for v in summary.values() if v.get("cached"))
        misses = len(summary) - hits
        log.info(
            "risk_cache_precompute: %d frameworks processed — %d cache hits, %d simulations run",
            len(summary),
            hits,
            misses,
        )

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
