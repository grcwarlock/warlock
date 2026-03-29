"""Unified Readiness-to-Audit View.

Combines readiness score, timeline projection, and prioritized gap list
into a single assessment for audit preparedness.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ControlResult, POAM, Remediation

log = logging.getLogger(__name__)

# Effort estimates by severity (person-days)
_EFFORT_MAP: dict[str, dict[str, float]] = {
    "critical": {"label": "L", "days": 10.0},
    "high": {"label": "L", "days": 7.0},
    "medium": {"label": "M", "days": 3.0},
    "low": {"label": "S", "days": 1.0},
    "info": {"label": "S", "days": 0.5},
}

# Score impact weights by severity (points toward 100)
_IMPACT_WEIGHTS: dict[str, float] = {
    "critical": 5.0,
    "high": 3.0,
    "medium": 1.5,
    "low": 0.5,
    "info": 0.1,
}


class ReadinessAssessor:
    """Computes audit readiness score, timeline projections, and prioritized gaps."""

    # ------------------------------------------------------------------
    # Core readiness score
    # ------------------------------------------------------------------

    def score(
        self,
        session: Session,
        framework: str,
        *,
        system_id: str | None = None,
    ) -> dict:
        """Compute a readiness score (0-100) for a framework.

        Score = (compliant controls / total assessed controls) * 100

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier (e.g. "soc2", "nist_800_53").
            system_id: Optional system profile filter.

        Returns:
            Dict with score, total, compliant, non_compliant, partial,
            not_assessed counts, and breakdown.
        """
        q = session.query(
            ControlResult.control_id,
            ControlResult.status,
            ControlResult.severity,
        ).filter(ControlResult.framework == framework)

        if system_id:
            q = q.filter(ControlResult.system_profile_id == system_id)

        # Deduplicate: take latest result per control

        subq = (
            session.query(
                ControlResult.control_id,
                func.max(ControlResult.assessed_at).label("latest"),
            )
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.control_id)
            .subquery()
        )

        if system_id:
            subq = (
                session.query(
                    ControlResult.control_id,
                    func.max(ControlResult.assessed_at).label("latest"),
                )
                .filter(
                    ControlResult.framework == framework,
                    ControlResult.system_profile_id == system_id,
                )
                .group_by(ControlResult.control_id)
                .subquery()
            )

        results = (
            session.query(ControlResult)
            .join(
                subq,
                (ControlResult.control_id == subq.c.control_id)
                & (ControlResult.assessed_at == subq.c.latest),
            )
            .filter(ControlResult.framework == framework)
            .all()
        )

        if not results:
            return {
                "framework": framework,
                "score": 0.0,
                "total": 0,
                "compliant": 0,
                "non_compliant": 0,
                "partial": 0,
                "not_assessed": 0,
                "not_applicable": 0,
            }

        counts: dict[str, int] = {
            "compliant": 0,
            "non_compliant": 0,
            "partial": 0,
            "not_assessed": 0,
            "not_applicable": 0,
        }
        for r in results:
            status = r.status or "not_assessed"
            # Normalize extended statuses
            if status in ("risk_accepted", "inherited_compliant"):
                counts["compliant"] = counts.get("compliant", 0) + 1
            elif status in ("inherited_at_risk",):
                counts["partial"] = counts.get("partial", 0) + 1
            elif status in counts:
                counts[status] = counts[status] + 1
            else:
                counts["not_assessed"] = counts.get("not_assessed", 0) + 1

        assessable = counts["compliant"] + counts["non_compliant"] + counts["partial"]
        total = assessable + counts["not_assessed"]

        if total == 0:
            raw_score = 0.0
        else:
            # Compliant = full credit, partial = half credit
            raw_score = ((counts["compliant"] + counts["partial"] * 0.5) / total) * 100

        return {
            "framework": framework,
            "score": round(raw_score, 1),
            "total": len(results),
            **counts,
        }

    # ------------------------------------------------------------------
    # Timeline projection
    # ------------------------------------------------------------------

    def timeline(
        self,
        session: Session,
        framework: str,
        target_score: float = 85.0,
        *,
        system_id: str | None = None,
        lookback_days: int = 30,
    ) -> dict:
        """Project days to reach target readiness score.

        Uses historical remediation velocity (controls moved to compliant
        over the lookback period) to estimate time to target.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            target_score: Target readiness score (0-100).
            system_id: Optional system profile filter.
            lookback_days: Days to look back for velocity calculation.

        Returns:
            Dict with current_score, target_score, gap_controls,
            velocity (controls/week), projected_days, projected_date.
        """
        current = self.score(session, framework, system_id=system_id)
        current_score = current["score"]

        if current_score >= target_score:
            return {
                "framework": framework,
                "current_score": current_score,
                "target_score": target_score,
                "gap_controls": 0,
                "velocity_per_week": 0.0,
                "projected_days": 0,
                "projected_date": datetime.now(timezone.utc).isoformat(),
                "status": "target_met",
            }

        total = current["total"]
        if total == 0:
            return {
                "framework": framework,
                "current_score": 0.0,
                "target_score": target_score,
                "gap_controls": 0,
                "velocity_per_week": 0.0,
                "projected_days": -1,
                "projected_date": None,
                "status": "no_data",
            }

        # How many more controls need to be compliant?
        needed_compliant = math.ceil((target_score / 100) * total)
        current_compliant = current["compliant"]
        gap_controls = max(0, needed_compliant - current_compliant)

        # Calculate velocity: closed remediations in lookback period
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        closed_count = (
            session.query(func.count(Remediation.id))
            .filter(
                Remediation.framework == framework,
                Remediation.status == "closed",
                Remediation.closed_at >= cutoff,
            )
            .scalar()
            or 0
        )

        # Also count POA&Ms that were completed/verified
        poam_closed = (
            session.query(func.count(POAM.id))
            .filter(
                POAM.framework == framework,
                POAM.status.in_(["completed", "verified"]),
            )
            .scalar()
            or 0
        )

        total_velocity = closed_count + poam_closed
        weeks = lookback_days / 7.0
        velocity_per_week = total_velocity / weeks if weeks > 0 else 0.0

        if velocity_per_week <= 0:
            # No remediation activity — cannot project
            return {
                "framework": framework,
                "current_score": current_score,
                "target_score": target_score,
                "gap_controls": gap_controls,
                "velocity_per_week": 0.0,
                "projected_days": -1,
                "projected_date": None,
                "status": "no_velocity",
            }

        projected_weeks = gap_controls / velocity_per_week
        projected_days = math.ceil(projected_weeks * 7)
        projected_date = datetime.now(timezone.utc) + timedelta(days=projected_days)

        return {
            "framework": framework,
            "current_score": current_score,
            "target_score": target_score,
            "gap_controls": gap_controls,
            "velocity_per_week": round(velocity_per_week, 1),
            "projected_days": projected_days,
            "projected_date": projected_date.isoformat(),
            "status": "projected",
        }

    # ------------------------------------------------------------------
    # Prioritized gap list
    # ------------------------------------------------------------------

    def gaps(
        self,
        session: Session,
        framework: str,
        *,
        system_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Get prioritized gap list for a framework.

        Ranks non-compliant/partial controls by effort (severity-based)
        and impact on readiness score.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            system_id: Optional system profile filter.
            limit: Max results.

        Returns:
            List of dicts sorted by priority (highest first), each with
            control_id, status, severity, effort, impact, priority_score,
            remediation_summary.
        """
        # Get latest results per control that are not compliant
        subq = (
            session.query(
                ControlResult.control_id,
                func.max(ControlResult.assessed_at).label("latest"),
            )
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.control_id)
            .subquery()
        )

        q = (
            session.query(ControlResult)
            .join(
                subq,
                (ControlResult.control_id == subq.c.control_id)
                & (ControlResult.assessed_at == subq.c.latest),
            )
            .filter(
                ControlResult.framework == framework,
                ControlResult.status.in_(["non_compliant", "partial", "not_assessed"]),
            )
        )

        if system_id:
            q = q.filter(ControlResult.system_profile_id == system_id)

        results = q.limit(limit * 2).all()  # over-fetch for sorting

        gaps = []
        for r in results:
            severity = r.severity or "medium"
            effort_info = _EFFORT_MAP.get(severity, _EFFORT_MAP["medium"])
            impact = _IMPACT_WEIGHTS.get(severity, 1.0)

            # Priority = impact / effort (higher = fix first)
            effort_days = effort_info["days"]
            priority_score = (impact / effort_days) * 100 if effort_days > 0 else 0

            gaps.append(
                {
                    "control_id": r.control_id,
                    "status": r.status,
                    "severity": severity,
                    "effort": effort_info["label"],
                    "effort_days": effort_days,
                    "impact": impact,
                    "priority_score": round(priority_score, 1),
                    "remediation_summary": r.remediation_summary or "",
                    "assertion_name": r.assertion_name or "",
                }
            )

        # Sort by priority score descending
        gaps.sort(key=lambda g: g["priority_score"], reverse=True)
        return gaps[:limit]
