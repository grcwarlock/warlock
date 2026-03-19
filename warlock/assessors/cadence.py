"""Continuous monitoring cadence tracking.

Compares evidence freshness against required monitoring frequencies
per NIST 800-53A and FedRAMP ConMon guidance.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from warlock.db.models import ControlMapping, ControlResult, Finding

log = logging.getLogger(__name__)

# Frequency → maximum allowed hours between evidence collections
FREQUENCY_HOURS: dict[str, float] = {
    "daily": 24.0,
    "weekly": 168.0,
    "monthly": 720.0,      # 30 days
    "quarterly": 2160.0,   # 90 days
    "annual": 8760.0,      # 365 days
}


@dataclass
class MonitoringCadence:
    framework: str
    control_id: str
    required_frequency: str
    required_hours: float
    last_evidence_at: datetime | None
    hours_since: float | None
    is_stale: bool
    staleness_ratio: float  # 1.0 = at threshold, >1.0 = overdue, <1.0 = fresh


class CadenceChecker:
    """Checks whether evidence collection meets required monitoring frequencies."""

    def check_control(
        self,
        session: Session,
        framework: str,
        control_id: str,
    ) -> MonitoringCadence:
        """Check cadence for a single control."""
        # Get monitoring frequency from the most recent mapping
        freq_row = (
            session.query(ControlMapping.monitoring_frequency)
            .filter(
                ControlMapping.framework == framework,
                ControlMapping.control_id == control_id,
                ControlMapping.monitoring_frequency.isnot(None),
            )
            .first()
        )
        frequency = freq_row[0] if freq_row else "monthly"
        required_hours = FREQUENCY_HOURS.get(frequency, 720.0)

        # Find the most recent evidence timestamp
        latest = (
            session.query(func.max(ControlResult.assessed_at))
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id == control_id,
            )
            .scalar()
        )

        now = datetime.now(timezone.utc)

        if latest is None:
            return MonitoringCadence(
                framework=framework,
                control_id=control_id,
                required_frequency=frequency,
                required_hours=required_hours,
                last_evidence_at=None,
                hours_since=None,
                is_stale=True,
                staleness_ratio=float("inf"),
            )

        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)

        hours_since = (now - latest).total_seconds() / 3600
        staleness_ratio = hours_since / required_hours if required_hours > 0 else 0.0

        return MonitoringCadence(
            framework=framework,
            control_id=control_id,
            required_frequency=frequency,
            required_hours=required_hours,
            last_evidence_at=latest,
            hours_since=round(hours_since, 2),
            is_stale=staleness_ratio > 1.0,
            staleness_ratio=round(staleness_ratio, 3),
        )

    def check_framework(
        self,
        session: Session,
        framework: str,
    ) -> list[MonitoringCadence]:
        """Check cadence for all controls in a framework."""
        control_rows = (
            session.query(distinct(ControlResult.control_id))
            .filter(ControlResult.framework == framework)
            .all()
        )
        control_ids = sorted([row[0] for row in control_rows])
        return [self.check_control(session, framework, cid) for cid in control_ids]

    def check_all(
        self,
        session: Session,
    ) -> dict[str, list[MonitoringCadence]]:
        """Check cadence across all frameworks."""
        framework_rows = (
            session.query(distinct(ControlResult.framework)).all()
        )
        frameworks = sorted([row[0] for row in framework_rows])
        return {fw: self.check_framework(session, fw) for fw in frameworks}

    def get_stale_controls(
        self,
        session: Session,
        framework: str | None = None,
    ) -> list[MonitoringCadence]:
        """Return only stale controls, optionally filtered by framework."""
        if framework:
            cadences = self.check_framework(session, framework)
        else:
            all_cadences = self.check_all(session)
            cadences = [c for clist in all_cadences.values() for c in clist]

        return sorted(
            [c for c in cadences if c.is_stale],
            key=lambda c: c.staleness_ratio,
            reverse=True,
        )
