"""Pipeline observability metrics — Prometheus-compatible export.

Tracks throughput (events/sec), latency (per stage), error rates,
and queue depth. Metrics are collected in-process and exported as
Prometheus text format for scraping.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

log = logging.getLogger(__name__)


@dataclass
class StageMetrics:
    """Metrics for a single pipeline stage."""

    events_processed: int = 0
    events_errored: int = 0
    total_latency_ms: float = 0.0
    last_event_at: datetime | None = None

    @property
    def avg_latency_ms(self) -> float:
        if self.events_processed == 0:
            return 0.0
        return self.total_latency_ms / self.events_processed

    @property
    def error_rate(self) -> float:
        total = self.events_processed + self.events_errored
        if total == 0:
            return 0.0
        return self.events_errored / total


@dataclass
class PipelineMetricsSnapshot:
    """Point-in-time snapshot of all pipeline metrics."""

    stages: dict[str, StageMetrics] = field(default_factory=dict)
    total_events: int = 0
    total_errors: int = 0
    uptime_seconds: float = 0.0
    queue_depth: int = 0
    active_connectors: int = 0
    last_run_id: str | None = None
    last_run_at: datetime | None = None
    throughput_eps: float = 0.0  # events per second (rolling window)


class PipelineMetrics:
    """Thread-safe pipeline metrics collector.

    Records per-stage event counts, latencies, and error rates.
    Provides Prometheus text export and structured snapshots.
    """

    STAGE_NAMES = ("collection", "normalization", "mapping", "assessment", "export")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stages: dict[str, StageMetrics] = {name: StageMetrics() for name in self.STAGE_NAMES}
        self._started_at = time.monotonic()
        self._start_wall = datetime.now(timezone.utc)
        self._queue_depth = 0
        self._active_connectors = 0
        self._last_run_id: str | None = None
        self._last_run_at: datetime | None = None
        self._total_events = 0
        self._total_errors = 0
        # Rolling window for throughput (last 60s of event timestamps)
        self._recent_events: list[float] = []

    def record_event(self, stage: str, latency_ms: float = 0.0, error: bool = False) -> None:
        """Record a processed event for a stage."""
        now = time.monotonic()
        with self._lock:
            metrics = self._stages.get(stage)
            if metrics is None:
                metrics = StageMetrics()
                self._stages[stage] = metrics

            if error:
                metrics.events_errored += 1
                self._total_errors += 1
            else:
                metrics.events_processed += 1
                metrics.total_latency_ms += latency_ms
                self._total_events += 1

            metrics.last_event_at = datetime.now(timezone.utc)

            # Rolling window for throughput
            self._recent_events.append(now)
            # Trim events older than 60s
            cutoff = now - 60.0
            self._recent_events = [t for t in self._recent_events if t > cutoff]

    def set_queue_depth(self, depth: int) -> None:
        """Update current queue depth."""
        with self._lock:
            self._queue_depth = depth

    def set_active_connectors(self, count: int) -> None:
        """Update number of active connectors."""
        with self._lock:
            self._active_connectors = count

    def record_run(self, run_id: str) -> None:
        """Record a pipeline run completion."""
        with self._lock:
            self._last_run_id = run_id
            self._last_run_at = datetime.now(timezone.utc)

    def snapshot(self) -> PipelineMetricsSnapshot:
        """Take a point-in-time snapshot of all metrics."""
        now = time.monotonic()
        with self._lock:
            stages = {}
            for name, m in self._stages.items():
                stages[name] = StageMetrics(
                    events_processed=m.events_processed,
                    events_errored=m.events_errored,
                    total_latency_ms=m.total_latency_ms,
                    last_event_at=m.last_event_at,
                )

            # Calculate throughput from rolling window
            cutoff = now - 60.0
            recent = [t for t in self._recent_events if t > cutoff]
            window = min(now - self._started_at, 60.0)
            throughput = len(recent) / window if window > 0 else 0.0

            return PipelineMetricsSnapshot(
                stages=stages,
                total_events=self._total_events,
                total_errors=self._total_errors,
                uptime_seconds=now - self._started_at,
                queue_depth=self._queue_depth,
                active_connectors=self._active_connectors,
                last_run_id=self._last_run_id,
                last_run_at=self._last_run_at,
                throughput_eps=throughput,
            )

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text exposition format."""
        snap = self.snapshot()
        lines: list[str] = []

        lines.append("# HELP warlock_pipeline_events_total Total events processed per stage")
        lines.append("# TYPE warlock_pipeline_events_total counter")
        for stage, m in snap.stages.items():
            lines.append(f'warlock_pipeline_events_total{{stage="{stage}"}} {m.events_processed}')

        lines.append("# HELP warlock_pipeline_errors_total Total errors per stage")
        lines.append("# TYPE warlock_pipeline_errors_total counter")
        for stage, m in snap.stages.items():
            lines.append(f'warlock_pipeline_errors_total{{stage="{stage}"}} {m.events_errored}')

        lines.append("# HELP warlock_pipeline_latency_avg_ms Average latency per stage (ms)")
        lines.append("# TYPE warlock_pipeline_latency_avg_ms gauge")
        for stage, m in snap.stages.items():
            lines.append(
                f'warlock_pipeline_latency_avg_ms{{stage="{stage}"}} {m.avg_latency_ms:.2f}'
            )

        lines.append("# HELP warlock_pipeline_error_rate Error rate per stage (0-1)")
        lines.append("# TYPE warlock_pipeline_error_rate gauge")
        for stage, m in snap.stages.items():
            lines.append(f'warlock_pipeline_error_rate{{stage="{stage}"}} {m.error_rate:.4f}')

        lines.append("# HELP warlock_pipeline_throughput_eps Events per second (60s window)")
        lines.append("# TYPE warlock_pipeline_throughput_eps gauge")
        lines.append(f"warlock_pipeline_throughput_eps {snap.throughput_eps:.2f}")

        lines.append("# HELP warlock_pipeline_queue_depth Current queue depth")
        lines.append("# TYPE warlock_pipeline_queue_depth gauge")
        lines.append(f"warlock_pipeline_queue_depth {snap.queue_depth}")

        lines.append("# HELP warlock_pipeline_active_connectors Active connectors")
        lines.append("# TYPE warlock_pipeline_active_connectors gauge")
        lines.append(f"warlock_pipeline_active_connectors {snap.active_connectors}")

        lines.append("# HELP warlock_pipeline_uptime_seconds Pipeline uptime in seconds")
        lines.append("# TYPE warlock_pipeline_uptime_seconds gauge")
        lines.append(f"warlock_pipeline_uptime_seconds {snap.uptime_seconds:.0f}")

        lines.append("# HELP warlock_pipeline_events_total_all Total events across all stages")
        lines.append("# TYPE warlock_pipeline_events_total_all counter")
        lines.append(f"warlock_pipeline_events_total_all {snap.total_events}")

        lines.append("# HELP warlock_pipeline_errors_total_all Total errors across all stages")
        lines.append("# TYPE warlock_pipeline_errors_total_all counter")
        lines.append(f"warlock_pipeline_errors_total_all {snap.total_errors}")

        lines.append("")
        return "\n".join(lines)

    def reset(self) -> None:
        """Reset all metrics (for testing)."""
        with self._lock:
            for m in self._stages.values():
                m.events_processed = 0
                m.events_errored = 0
                m.total_latency_ms = 0.0
                m.last_event_at = None
            self._total_events = 0
            self._total_errors = 0
            self._queue_depth = 0
            self._active_connectors = 0
            self._recent_events.clear()
            self._started_at = time.monotonic()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: PipelineMetrics | None = None
_instance_lock = threading.Lock()


def get_pipeline_metrics() -> PipelineMetrics:
    """Return the global PipelineMetrics singleton."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = PipelineMetrics()
    return _instance


def get_metrics_from_db() -> PipelineMetricsSnapshot:
    """Build a metrics snapshot from OLTP data (for CLI / cold-start).

    When the pipeline is not actively running, we can still derive useful
    metrics from the pipeline_runs and connector_runs tables.
    """
    from sqlalchemy import func

    from warlock.db.engine import get_read_session, init_db
    from warlock.db.models import PipelineRun
    from warlock.utils import ensure_aware

    init_db()
    snap = PipelineMetricsSnapshot()

    with get_read_session() as session:
        # Latest pipeline run
        latest_run = session.query(PipelineRun).order_by(PipelineRun.started_at.desc()).first()
        if latest_run:
            snap.last_run_id = latest_run.id
            snap.last_run_at = (
                ensure_aware(latest_run.started_at) if latest_run.started_at else None
            )
            if latest_run.duration_seconds:
                snap.uptime_seconds = latest_run.duration_seconds

            # Derive per-stage counts from run stats
            snap.stages["collection"] = StageMetrics(
                events_processed=latest_run.raw_events_collected or 0,
            )
            snap.stages["normalization"] = StageMetrics(
                events_processed=latest_run.findings_normalized or 0,
            )
            snap.stages["mapping"] = StageMetrics(
                events_processed=latest_run.controls_mapped or 0,
            )

            # Throughput from last run
            if latest_run.duration_seconds and latest_run.duration_seconds > 0:
                total = (
                    (latest_run.raw_events_collected or 0)
                    + (latest_run.findings_normalized or 0)
                    + (latest_run.controls_mapped or 0)
                )
                snap.throughput_eps = total / latest_run.duration_seconds

        # Total events from all runs
        totals = session.query(
            func.sum(PipelineRun.raw_events_collected),
            func.sum(PipelineRun.findings_normalized),
            func.sum(PipelineRun.controls_mapped),
        ).first()
        if totals and totals[0] is not None:
            snap.total_events = (totals[0] or 0) + (totals[1] or 0) + (totals[2] or 0)

        # Error count
        error_count = session.query(func.sum(PipelineRun.connectors_failed)).scalar()
        snap.total_errors = error_count or 0

        # Active connectors (from latest run)
        if latest_run:
            snap.active_connectors = (latest_run.connectors_succeeded or 0) + (
                latest_run.connectors_failed or 0
            )

    return snap
