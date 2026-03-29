"""Compliance velocity metrics: MTTC, gap closure rate, compliance debt,
evidence freshness decay curves.

Reads from PostureSnapshot, ControlResult, Issue, POAM, and EvidenceRequest
to compute throughput and debt metrics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlResult,
    EvidenceRequest,
    Issue,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


@dataclass
class VelocityMetrics:
    """Compliance velocity snapshot."""

    framework: str | None = None
    # MTTC: Mean Time to Compliance (hours)
    mttc_hours: float | None = None
    # Gap closure rate (gaps closed per week)
    gap_closure_rate: float = 0.0
    # Compliance debt (accumulated age-weighted severity score)
    compliance_debt: float = 0.0
    # Evidence freshness stats
    avg_evidence_age_hours: float | None = None
    stale_evidence_count: int = 0
    # Counts
    open_gaps: int = 0
    closed_gaps_last_30d: int = 0
    total_controls: int = 0
    compliant_controls: int = 0


def compute_velocity(
    session: Session,
    framework: str | None = None,
    lookback_days: int = 90,
) -> VelocityMetrics:
    """Compute compliance velocity metrics.

    Parameters
    ----------
    session: SQLAlchemy session
    framework: optional framework filter
    lookback_days: number of days to look back for trend analysis
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=lookback_days)
    metrics = VelocityMetrics(framework=framework)

    # ---- Control result counts ----
    q = session.query(ControlResult)
    if framework:
        q = q.filter(ControlResult.framework == framework)
    results = q.all()
    metrics.total_controls = len(results)
    metrics.compliant_controls = sum(1 for r in results if r.status == "compliant")

    # ---- Open gaps (non-compliant controls) ----
    metrics.open_gaps = sum(1 for r in results if r.status in ("non_compliant", "partial"))

    # ---- MTTC: from issues closed in the lookback window ----
    iq = session.query(Issue).filter(
        Issue.status.in_(["closed", "verified", "remediated"]),
    )
    if framework:
        iq = iq.filter(Issue.framework == framework)
    closed_issues = iq.all()

    ttc_values = []
    closed_in_window = 0
    for issue in closed_issues:
        created = ensure_aware(issue.created_at)
        remediated = ensure_aware(issue.remediated_at) if issue.remediated_at else None
        verified = ensure_aware(issue.verified_at) if issue.verified_at else None
        resolved_at = verified or remediated
        if resolved_at and created:
            if resolved_at >= cutoff:
                closed_in_window += 1
            delta = (resolved_at - created).total_seconds() / 3600.0
            if delta > 0:
                ttc_values.append(delta)

    if ttc_values:
        metrics.mttc_hours = sum(ttc_values) / len(ttc_values)

    metrics.closed_gaps_last_30d = closed_in_window
    weeks = lookback_days / 7.0
    metrics.gap_closure_rate = closed_in_window / weeks if weeks > 0 else 0.0

    # ---- Compliance debt: age-weighted severity of open gaps ----
    _severity_weight = {
        "critical": 4.0,
        "high": 3.0,
        "medium": 2.0,
        "low": 1.0,
        "info": 0.5,
    }
    open_issues = session.query(Issue).filter(
        Issue.status.notin_(["closed", "verified", "risk_accepted"])
    )
    if framework:
        open_issues = open_issues.filter(Issue.framework == framework)
    debt = 0.0
    for issue in open_issues.all():
        age_days = (now - ensure_aware(issue.created_at)).days
        weight = _severity_weight.get(issue.priority or "medium", 2.0)
        debt += age_days * weight
    metrics.compliance_debt = debt

    # ---- Evidence freshness ----
    eq = session.query(EvidenceRequest).filter(EvidenceRequest.status == "completed")
    if framework:
        eq = eq.filter(EvidenceRequest.framework == framework)
    evidence = eq.all()
    if evidence:
        ages = []
        stale = 0
        for e in evidence:
            if e.completed_at:
                age_h = (now - ensure_aware(e.completed_at)).total_seconds() / 3600.0
                ages.append(age_h)
                if age_h > 24 * 90:  # 90 days = stale
                    stale += 1
        if ages:
            metrics.avg_evidence_age_hours = sum(ages) / len(ages)
        metrics.stale_evidence_count = stale

    return metrics
