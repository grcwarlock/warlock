"""Compliance benchmarking — synthetic peer comparison.

Generates simulated peer benchmark data (clearly labeled as synthetic)
and computes percentile rankings for framework compliance scores.

Industry benchmarks are derived from published survey data ranges and
randomized to avoid implying specific organizations. All data is
explicitly labeled as simulated.
"""

from __future__ import annotations

import hashlib
import logging
import random
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from warlock.db.models import ControlResult

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Synthetic benchmark distributions per framework
# ---------------------------------------------------------------------------

# Each entry: (mean_pct, stddev_pct) — derived from published industry surveys
_INDUSTRY_DISTRIBUTIONS: dict[str, tuple[float, float]] = {
    "nist_800_53": (62.0, 15.0),
    "iso_27001": (68.0, 14.0),
    "soc2": (71.0, 12.0),
    "hipaa": (65.0, 16.0),
    "pci_dss_v4": (69.0, 13.0),
    "cmmc_l2": (55.0, 18.0),
    "fedramp": (58.0, 16.0),
    "gdpr": (64.0, 15.0),
    "nist_csf_2": (66.0, 14.0),
    "ucf": (60.0, 16.0),
    "iso_27701": (58.0, 17.0),
    "iso_42001": (45.0, 20.0),
    "eu_ai_act": (40.0, 22.0),
    "sec_cyber": (55.0, 18.0),
    "soc2_points_of_focus": (71.0, 12.0),
}

# Fallback for unknown frameworks
_DEFAULT_DISTRIBUTION = (60.0, 16.0)

# Number of synthetic peers to generate
_PEER_COUNT = 200


@dataclass
class BenchmarkResult:
    """Result of a single framework benchmark comparison."""

    framework: str
    your_score: float
    percentile: float
    peer_count: int
    peer_mean: float
    peer_median: float
    peer_p25: float
    peer_p75: float
    peer_min: float
    peer_max: float
    label: str = ""  # "Above Average", "Below Average", etc.


@dataclass
class BenchmarkReport:
    """Complete benchmark report across frameworks."""

    results: list[BenchmarkResult] = field(default_factory=list)
    generated_at: str = ""
    disclaimer: str = (
        "Peer benchmark data is SIMULATED based on published industry survey ranges. "
        "It does not represent any specific organization's compliance posture. "
        "Use for directional guidance only."
    )


def _generate_peer_scores(
    framework: str,
    count: int = _PEER_COUNT,
    seed: str | None = None,
) -> list[float]:
    """Generate synthetic peer compliance scores for a framework.

    Uses a deterministic seed derived from framework name so results
    are reproducible within a session.
    """
    mean, stddev = _INDUSTRY_DISTRIBUTIONS.get(framework, _DEFAULT_DISTRIBUTION)

    # Deterministic seed from framework name + fixed salt
    seed_val = seed or hashlib.sha256(f"warlock-benchmark-{framework}".encode()).hexdigest()
    rng = random.Random(seed_val)

    scores: list[float] = []
    for _ in range(count):
        score = rng.gauss(mean, stddev)
        score = max(0.0, min(100.0, score))
        scores.append(round(score, 1))

    return sorted(scores)


def _percentile_rank(sorted_scores: list[float], value: float) -> float:
    """Compute percentile rank of value within sorted scores."""
    if not sorted_scores:
        return 50.0
    count_below = sum(1 for s in sorted_scores if s < value)
    count_equal = sum(1 for s in sorted_scores if s == value)
    percentile = (count_below + 0.5 * count_equal) / len(sorted_scores) * 100
    return round(min(99.9, max(0.1, percentile)), 1)


def _score_label(percentile: float) -> str:
    """Human-readable label for a percentile rank."""
    if percentile >= 90:
        return "Top Performer"
    if percentile >= 75:
        return "Above Average"
    if percentile >= 50:
        return "Average"
    if percentile >= 25:
        return "Below Average"
    return "Needs Improvement"


def compute_framework_score(session: Session, framework: str) -> float:
    """Compute the current compliance pass rate for a framework.

    Returns percentage (0-100) of controls in compliant status.
    """
    results = session.query(ControlResult).filter(ControlResult.framework == framework).all()
    if not results:
        return 0.0

    compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
    return round(compliant / len(results) * 100, 1)


def benchmark_framework(
    session: Session,
    framework: str,
) -> BenchmarkResult:
    """Benchmark a single framework against synthetic peers."""
    your_score = compute_framework_score(session, framework)
    peers = _generate_peer_scores(framework)
    percentile = _percentile_rank(peers, your_score)

    n = len(peers)
    return BenchmarkResult(
        framework=framework,
        your_score=your_score,
        percentile=percentile,
        peer_count=n,
        peer_mean=round(sum(peers) / n, 1) if n else 0.0,
        peer_median=peers[n // 2] if n else 0.0,
        peer_p25=peers[n // 4] if n else 0.0,
        peer_p75=peers[3 * n // 4] if n else 0.0,
        peer_min=peers[0] if n else 0.0,
        peer_max=peers[-1] if n else 0.0,
        label=_score_label(percentile),
    )


def benchmark_all_frameworks(session: Session) -> BenchmarkReport:
    """Benchmark all active frameworks against synthetic peers."""
    from datetime import datetime, timezone

    frameworks = (
        session.query(ControlResult.framework).distinct().order_by(ControlResult.framework).all()
    )

    report = BenchmarkReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    for (fw,) in frameworks:
        result = benchmark_framework(session, fw)
        report.results.append(result)

    return report
