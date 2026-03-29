"""Continuous Authorization to Operate (cATO) engine.

Implements real-time posture monitoring against FedRAMP baselines,
significant change detection, and ConMon deliverable automation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import (
    ComplianceDrift,
    ControlResult,
    POAM,
    PostureSnapshot,
    SystemProfile,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# FedRAMP Moderate baseline: minimum acceptable posture score
FEDRAMP_MOD_THRESHOLD = 80.0
# Significant change: drift of N percentage points triggers reauthorization review
SIGNIFICANT_CHANGE_THRESHOLD = 10.0


@dataclass
class AuthorizationStatus:
    """Current cATO authorization posture."""

    system_id: str | None = None
    system_name: str = ""
    framework: str = "fedramp"
    current_score: float = 0.0
    threshold: float = FEDRAMP_MOD_THRESHOLD
    authorized: bool = False
    significant_changes: list[dict[str, Any]] = field(default_factory=list)
    drift_events: list[dict[str, Any]] = field(default_factory=list)
    open_poams: int = 0
    critical_poams: int = 0
    overdue_poams: int = 0
    conmon_deliverables: list[dict[str, Any]] = field(default_factory=list)
    last_assessment: datetime | None = None
    days_since_assessment: int | None = None


def evaluate_authorization(
    session: Session,
    framework: str = "fedramp",
    system_id: str | None = None,
    threshold: float = FEDRAMP_MOD_THRESHOLD,
) -> AuthorizationStatus:
    """Evaluate continuous authorization posture.

    Returns an AuthorizationStatus with current posture score,
    significant change detection, and ConMon deliverable status.
    """
    now = datetime.now(timezone.utc)
    status = AuthorizationStatus(
        system_id=system_id,
        framework=framework,
        threshold=threshold,
    )

    # Resolve system name
    if system_id:
        sp = session.query(SystemProfile).filter(SystemProfile.id == system_id).first()
        if sp:
            status.system_name = sp.name or sp.acronym or ""

    # ---- Current posture score ----
    rq = session.query(ControlResult).filter(ControlResult.framework == framework)
    if system_id:
        rq = rq.filter(ControlResult.system_profile_id == system_id)
    results = rq.all()

    if results:
        compliant = sum(1 for r in results if r.status in ("compliant", "inherited_compliant"))
        status.current_score = (compliant / len(results)) * 100.0

    status.authorized = status.current_score >= threshold

    # ---- Significant change detection via PostureSnapshot trend ----
    thirty_days_ago = now - timedelta(days=30)
    sq = (
        session.query(PostureSnapshot)
        .filter(
            PostureSnapshot.framework == framework,
            PostureSnapshot.snapshot_date >= thirty_days_ago,
        )
        .order_by(PostureSnapshot.snapshot_date)
    )
    snapshots = sq.all()

    if len(snapshots) >= 2:
        earliest_score = snapshots[0].posture_score or 0.0
        latest_score = snapshots[-1].posture_score or 0.0
        drift = earliest_score - latest_score
        if drift >= SIGNIFICANT_CHANGE_THRESHOLD:
            status.significant_changes.append(
                {
                    "type": "posture_degradation",
                    "description": (
                        f"Posture dropped {drift:.1f} points "
                        f"({earliest_score:.1f} -> {latest_score:.1f}) in 30 days"
                    ),
                    "severity": "high" if drift >= 20 else "medium",
                    "detected_at": now.isoformat(),
                }
            )

    # ---- Compliance drift events ----
    dq = (
        session.query(ComplianceDrift)
        .filter(ComplianceDrift.framework == framework)
        .order_by(ComplianceDrift.detected_at.desc())
        .limit(20)
    )
    for d in dq.all():
        status.drift_events.append(
            {
                "id": d.id[:8],
                "control_id": d.control_id,
                "from_status": d.previous_status,
                "to_status": d.current_status,
                "detected_at": ensure_aware(d.detected_at).isoformat(),
            }
        )

    # ---- POA&M status ----
    pq = session.query(POAM).filter(
        POAM.framework == framework,
        POAM.status.notin_(["completed", "verified", "cancelled"]),
    )
    if system_id:
        pq = pq.filter(POAM.system_profile_id == system_id)
    open_poams = pq.all()

    status.open_poams = len(open_poams)
    status.critical_poams = sum(1 for p in open_poams if p.severity in ("critical", "high"))
    status.overdue_poams = sum(
        1
        for p in open_poams
        if p.scheduled_completion and ensure_aware(p.scheduled_completion) < now
    )

    # ---- ConMon deliverables ----
    status.conmon_deliverables = [
        {
            "name": "Monthly vulnerability scan",
            "frequency": "monthly",
            "status": "due" if status.open_poams > 0 else "current",
        },
        {
            "name": "Quarterly POA&M update",
            "frequency": "quarterly",
            "status": "overdue" if status.overdue_poams > 0 else "current",
        },
        {
            "name": "Annual security assessment",
            "frequency": "annual",
            "status": "check",
        },
        {
            "name": "Significant change report",
            "frequency": "as-needed",
            "status": ("action_required" if status.significant_changes else "none_detected"),
        },
    ]

    return status
