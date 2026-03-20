"""Audit simulation.

Projects compliance posture at a future target date by checking
evidence staleness, overdue POA&Ms, expiring risk acceptances,
posture trends, and inherited control status.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import distinct
from sqlalchemy.orm import Session

from warlock.assessors.cadence import CadenceChecker
from warlock.assessors.posture import PostureTimeSeriesQuery
from warlock.db.models import (
    ControlInheritance,
    ControlResult,
    POAM,
    PostureSnapshot,
    RiskAcceptance,
)

log = logging.getLogger(__name__)


@dataclass
class AuditSimulationResult:
    """Projected compliance state at target_date."""

    framework: str
    target_date: datetime
    system_id: str | None

    total_controls: int = 0
    projected_coverage: float = 0.0  # 0.0-1.0

    stale_controls: list[dict] = field(default_factory=list)
    overdue_poams: list[dict] = field(default_factory=list)
    expiring_acceptances: list[dict] = field(default_factory=list)
    at_risk_controls: list[dict] = field(default_factory=list)


class AuditSimulator:
    """Simulates audit readiness at a future date."""

    def simulate(
        self,
        session: Session,
        framework: str,
        target_date: datetime,
        system_id: str | None = None,
    ) -> AuditSimulationResult:
        """Project compliance posture at target_date.

        Checks:
        1. Evidence staleness by target_date (per monitoring frequency)
        2. Open POA&Ms that will be overdue by target_date
        3. Active risk acceptances that expire before target_date
        4. Posture trend projections
        5. Inherited control status from providers

        Args:
            session: SQLAlchemy session.
            framework: Framework to simulate.
            target_date: Future date to project to.
            system_id: Optional system profile filter.

        Returns:
            AuditSimulationResult with projected state.
        """
        if target_date.tzinfo is None:
            target_date = target_date.replace(tzinfo=timezone.utc)

        result = AuditSimulationResult(
            framework=framework,
            target_date=target_date,
            system_id=system_id,
        )

        # Get all controls for this framework
        query = session.query(distinct(ControlResult.control_id)).filter(
            ControlResult.framework == framework
        )
        if system_id:
            query = query.filter(ControlResult.system_profile_id == system_id)

        control_ids = sorted([row[0] for row in query.all()])
        result.total_controls = len(control_ids)

        if not control_ids:
            return result

        now = datetime.now(timezone.utc)
        hours_until_target = (target_date - now).total_seconds() / 3600

        compliant_count = 0
        cadence_checker = CadenceChecker()
        ts_query = PostureTimeSeriesQuery()

        for cid in control_ids:
            is_at_risk = False

            # --- 1. Check evidence staleness by target_date ---
            cadence = cadence_checker.check_control(session, framework, cid)
            if cadence.last_evidence_at:
                hours_at_target = (
                    cadence.hours_since + hours_until_target
                    if cadence.hours_since is not None
                    else hours_until_target
                )
                if hours_at_target > cadence.required_hours:
                    result.stale_controls.append(
                        {
                            "control_id": cid,
                            "frequency": cadence.required_frequency,
                            "hours_stale_at_target": round(hours_at_target, 1),
                            "threshold_hours": cadence.required_hours,
                        }
                    )
                    is_at_risk = True
            else:
                result.stale_controls.append(
                    {
                        "control_id": cid,
                        "frequency": cadence.required_frequency,
                        "hours_stale_at_target": None,
                        "threshold_hours": cadence.required_hours,
                    }
                )
                is_at_risk = True

            # --- 2. Posture trend projection ---
            ts = ts_query.query_control(session, framework, cid, days=90)
            if ts.trend == "degrading":
                # Project score at target_date
                days_ahead = hours_until_target / 24
                projected_score = (
                    ts.points[-1].posture_score if ts.points else 0
                ) + ts.trend_slope * days_ahead
                if projected_score < 50:
                    is_at_risk = True

            # --- 3. Check inherited control status ---
            if system_id:
                inh = (
                    session.query(ControlInheritance)
                    .filter(
                        ControlInheritance.system_profile_id == system_id,
                        ControlInheritance.framework == framework,
                        ControlInheritance.control_id == cid,
                        ControlInheritance.status == "active",
                        ControlInheritance.inheritance_type == "inherited",
                    )
                    .first()
                )
                if inh and inh.provider_system_id:
                    provider_snap = (
                        session.query(PostureSnapshot)
                        .filter(
                            PostureSnapshot.system_profile_id == inh.provider_system_id,
                            PostureSnapshot.framework == framework,
                            PostureSnapshot.control_id == cid,
                        )
                        .order_by(PostureSnapshot.snapshot_date.desc())
                        .first()
                    )
                    if not provider_snap or provider_snap.status != "compliant":
                        is_at_risk = True

            # --- Current posture for coverage calculation ---
            latest_snap = (
                session.query(PostureSnapshot)
                .filter(
                    PostureSnapshot.framework == framework,
                    PostureSnapshot.control_id == cid,
                )
                .order_by(PostureSnapshot.snapshot_date.desc())
                .first()
            )
            if (
                latest_snap
                and latest_snap.status
                in (
                    "compliant",
                    "inherited_compliant",
                    "risk_accepted",
                )
                and not is_at_risk
            ):
                compliant_count += 1

            if is_at_risk:
                result.at_risk_controls.append(
                    {
                        "control_id": cid,
                        "current_status": latest_snap.status if latest_snap else "unknown",
                        "trend": ts.trend if ts.points else "unknown",
                    }
                )

        # --- 4. Overdue POA&Ms by target_date ---
        open_poams = (
            session.query(POAM)
            .filter(
                POAM.framework == framework,
                POAM.scheduled_completion.isnot(None),
                POAM.scheduled_completion < target_date,
                ~POAM.status.in_({"completed", "verified", "closed"}),
            )
            .all()
        )
        for p in open_poams:
            result.overdue_poams.append(
                {
                    "poam_id": p.id,
                    "control_id": p.control_id,
                    "severity": p.severity,
                    "scheduled_completion": p.scheduled_completion.isoformat()
                    if p.scheduled_completion
                    else None,
                    "delay_count": p.delay_count or 0,
                }
            )

        # --- 5. Expiring risk acceptances ---
        expiring = (
            session.query(RiskAcceptance)
            .filter(
                RiskAcceptance.framework == framework,
                RiskAcceptance.status == "active",
                RiskAcceptance.expiry_date <= target_date,
            )
            .all()
        )
        for ra in expiring:
            result.expiring_acceptances.append(
                {
                    "acceptance_id": ra.id,
                    "control_id": ra.control_id,
                    "risk_level": ra.risk_level,
                    "expiry_date": ra.expiry_date.isoformat() if ra.expiry_date else None,
                }
            )

        # Projected coverage
        result.projected_coverage = (
            round(compliant_count / result.total_controls, 4) if result.total_controls > 0 else 0.0
        )

        log.info(
            "Audit simulation for %s at %s: coverage=%.1f%%, "
            "stale=%d, overdue_poams=%d, expiring_ra=%d, at_risk=%d",
            framework,
            target_date.date().isoformat(),
            result.projected_coverage * 100,
            len(result.stale_controls),
            len(result.overdue_poams),
            len(result.expiring_acceptances),
            len(result.at_risk_controls),
        )

        return result
