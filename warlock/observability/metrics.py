"""Prometheus metrics (optional).

Defines core GRC pipeline counters and histograms.  When
``prometheus_client`` is not installed, every metric object becomes a
lightweight no-op stub so callers can safely call ``.inc()`` /
``.observe()`` without guarding imports.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

_HAS_PROMETHEUS = False
try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest

    _HAS_PROMETHEUS = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# No-op stubs (used when prometheus_client is absent)
# ---------------------------------------------------------------------------


class _NoopMetric:
    """Drop-in replacement for Counter / Histogram / Gauge."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def inc(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def dec(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def set(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def observe(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def labels(self, *_args: Any, **_kwargs: Any) -> "_NoopMetric":
        return self


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

if _HAS_PROMETHEUS:
    pipeline_events_total = Counter(
        "warlock_pipeline_events_total",
        "Total raw events collected by the pipeline",
        ["source_type"],
    )
    findings_total = Counter(
        "warlock_findings_total",
        "Total findings normalised",
        ["severity"],
    )
    control_results_total = Counter(
        "warlock_control_results_total",
        "Total control assessment results",
        ["framework", "status"],
    )
    api_requests_total = Counter(
        "warlock_api_requests_total",
        "Total API requests",
        ["method", "path", "status_code"],
    )
    pipeline_duration_seconds = Histogram(
        "warlock_pipeline_duration_seconds",
        "Pipeline run duration in seconds",
    )
    active_connectors = Gauge(
        "warlock_active_connectors",
        "Number of active connectors",
    )
else:
    pipeline_events_total = _NoopMetric()  # type: ignore[assignment]
    findings_total = _NoopMetric()  # type: ignore[assignment]
    control_results_total = _NoopMetric()  # type: ignore[assignment]
    api_requests_total = _NoopMetric()  # type: ignore[assignment]
    pipeline_duration_seconds = _NoopMetric()  # type: ignore[assignment]
    active_connectors = _NoopMetric()  # type: ignore[assignment]


def metrics_response() -> bytes:
    """Return Prometheus exposition format bytes.

    Returns an empty byte string when ``prometheus_client`` is not installed.
    """
    if not _HAS_PROMETHEUS:
        return b""
    return generate_latest()
