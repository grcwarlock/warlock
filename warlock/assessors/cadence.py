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

from warlock.db.models import ControlMapping, ControlResult

log = logging.getLogger(__name__)

# Frequency → maximum allowed hours between evidence collections
FREQUENCY_HOURS: dict[str, float] = {
    "daily": 24.0,
    "weekly": 168.0,
    "monthly": 720.0,  # 30 days
    "quarterly": 2160.0,  # 90 days
    "annual": 8760.0,  # 365 days
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
        """Check cadence for all controls in a framework using batch queries."""
        now = datetime.now(timezone.utc)

        # Batch: get monitoring frequency per control
        freq_rows = (
            session.query(
                ControlMapping.control_id,
                ControlMapping.monitoring_frequency,
            )
            .filter(
                ControlMapping.framework == framework,
                ControlMapping.monitoring_frequency.isnot(None),
            )
            .distinct()
            .all()
        )
        freq_map = {cid: freq for cid, freq in freq_rows}

        # Batch: get latest evidence timestamp per control
        latest_rows = (
            session.query(
                ControlResult.control_id,
                func.max(ControlResult.assessed_at).label("latest"),
            )
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.control_id)
            .all()
        )

        cadences = []
        for control_id, latest in latest_rows:
            frequency = freq_map.get(control_id, "monthly")
            required_hours = FREQUENCY_HOURS.get(frequency, 720.0)

            if latest is None:
                cadences.append(
                    MonitoringCadence(
                        framework=framework,
                        control_id=control_id,
                        required_frequency=frequency,
                        required_hours=required_hours,
                        last_evidence_at=None,
                        hours_since=None,
                        is_stale=True,
                        staleness_ratio=float("inf"),
                    )
                )
                continue

            if latest.tzinfo is None:
                latest = latest.replace(tzinfo=timezone.utc)
            hours_since = (now - latest).total_seconds() / 3600
            staleness_ratio = hours_since / required_hours if required_hours > 0 else 0.0

            cadences.append(
                MonitoringCadence(
                    framework=framework,
                    control_id=control_id,
                    required_frequency=frequency,
                    required_hours=required_hours,
                    last_evidence_at=latest,
                    hours_since=round(hours_since, 2),
                    is_stale=staleness_ratio > 1.0,
                    staleness_ratio=round(staleness_ratio, 3),
                )
            )

        return cadences

    def check_all(
        self,
        session: Session,
    ) -> dict[str, list[MonitoringCadence]]:
        """Check cadence across all frameworks."""
        framework_rows = session.query(distinct(ControlResult.framework)).all()
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
