"""Periodic pipeline scheduler for continuous monitoring.

Runs the pipeline on a configurable schedule without requiring Celery.
Uses stdlib ``threading`` for background execution.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schedule definitions
# ---------------------------------------------------------------------------

DEFAULT_SCHEDULES: dict[str, dict[str, Any]] = {
    "pipeline_collect": {"interval_minutes": 60, "enabled": True},
    "posture_snapshot": {"interval_minutes": 1440, "enabled": True},   # daily
    "retention_purge": {"interval_minutes": 10080, "enabled": False},  # weekly
}


# ---------------------------------------------------------------------------
# PipelineScheduler
# ---------------------------------------------------------------------------


class PipelineScheduler:
    """Run the pipeline on a configurable interval in a background thread."""

    def __init__(self, interval_minutes: int = 60):
        self.interval = interval_minutes * 60  # seconds
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._run_count = 0
        self._last_run: datetime | None = None
        self._next_run: datetime | None = None
        self._last_error: str | None = None
        self._lock = threading.Lock()

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
        log.info("Scheduler started (interval=%ds)", self.interval)

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
        """Main loop: run pipeline, sleep, repeat."""
        while not self._stop_event.is_set():
            self._next_run = datetime.now(timezone.utc)
            self._execute_run()
            # Sleep in small increments so we can respond to stop quickly
            elapsed = 0.0
            while elapsed < self.interval and not self._stop_event.is_set():
                chunk = min(1.0, self.interval - elapsed)
                self._stop_event.wait(timeout=chunk)
                elapsed += chunk

            with self._lock:
                if not self._running:
                    break

    def _execute_run(self) -> None:
        """Execute a single pipeline run."""
        try:
            from warlock.db.engine import get_session, init_db
            from warlock.pipeline.bus import EventBus
            from warlock.pipeline.loader import build_pipeline

            init_db()
            bus = EventBus()
            pipeline = build_pipeline(bus)

            with get_session() as session:
                stats = pipeline.run(session)

            with self._lock:
                self._run_count += 1
                self._last_run = datetime.now(timezone.utc)
                self._last_error = None

            log.info(
                "Scheduled run #%d complete: %d events, %d findings, %d results",
                self._run_count,
                stats.raw_events_collected,
                stats.findings_normalized,
                stats.results_assessed,
            )
        except Exception as exc:
            with self._lock:
                self._run_count += 1
                self._last_run = datetime.now(timezone.utc)
                self._last_error = str(exc)
            log.exception("Scheduled pipeline run failed")

    @property
    def status(self) -> dict[str, Any]:
        """Return scheduler status: running, last_run, next_run, run_count."""
        with self._lock:
            next_run = None
            if self._running and self._last_run:
                from datetime import timedelta

                next_run = (self._last_run + timedelta(seconds=self.interval)).isoformat()
            elif self._running:
                next_run = "imminent"

            return {
                "running": self._running,
                "interval_minutes": self.interval // 60,
                "interval_seconds": self.interval,
                "last_run": self._last_run.isoformat() if self._last_run else None,
                "next_run": next_run,
                "run_count": self._run_count,
                "last_error": self._last_error,
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
