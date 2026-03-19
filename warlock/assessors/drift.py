"""Compliance drift detection.

Compares consecutive posture snapshots to identify status changes,
creates ComplianceDrift records, and correlates with ChangeEvents
for root cause analysis.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from warlock.db.models import (
    ChangeEvent,
    ComplianceDrift,
    ControlResult,
    Finding,
    PostureSnapshot,
)

log = logging.getLogger(__name__)

# Status ordering for drift direction classification
_COMPLIANT_STATUSES = frozenset({
    "compliant", "inherited_compliant", "risk_accepted",
})


class DriftDetector:
    """Detects compliance status changes between posture snapshots."""

    def detect(
        self,
        session: Session,
        framework: str | None = None,
    ) -> list[ComplianceDrift]:
        """Compare the latest two snapshots per control, create drift rows.

        For each (framework, control_id), finds the two most recent snapshots.
        If the status changed, creates a ComplianceDrift record.

        Args:
            session: SQLAlchemy session.
            framework: Optional framework filter.

        Returns:
            List of newly created ComplianceDrift rows.
        """
        # Get distinct (framework, control_id) pairs from snapshots
        pairs_query = session.query(
            PostureSnapshot.framework,
            PostureSnapshot.control_id,
        ).distinct()

        if framework:
            pairs_query = pairs_query.filter(
                PostureSnapshot.framework == framework
            )

        pairs = pairs_query.all()
        drifts: list[ComplianceDrift] = []

        for fw, cid in pairs:
            # Get the two most recent snapshots
            latest_two = (
                session.query(PostureSnapshot)
                .filter(
                    PostureSnapshot.framework == fw,
                    PostureSnapshot.control_id == cid,
                )
                .order_by(PostureSnapshot.snapshot_date.desc())
                .limit(2)
                .all()
            )

            if len(latest_two) < 2:
                continue

            current, previous = latest_two[0], latest_two[1]

            if current.status == previous.status:
                continue

            # Determine drift direction
            curr_compliant = current.status in _COMPLIANT_STATUSES
            prev_compliant = previous.status in _COMPLIANT_STATUSES
            if curr_compliant and not prev_compliant:
                direction = "improved"
            elif not curr_compliant and prev_compliant:
                direction = "degraded"
            elif (current.posture_score or 0) > (previous.posture_score or 0):
                direction = "improved"
            else:
                direction = "degraded"

            # Check for existing drift record for this exact transition
            existing = (
                session.query(ComplianceDrift)
                .filter(
                    ComplianceDrift.framework == fw,
                    ComplianceDrift.control_id == cid,
                    ComplianceDrift.snapshot_id == current.id,
                )
                .first()
            )
            if existing:
                continue

            drift = ComplianceDrift(
                framework=fw,
                control_id=cid,
                system_profile_id=current.system_profile_id,
                previous_status=previous.status,
                new_status=current.status,
                drift_direction=direction,
                previous_posture_score=previous.posture_score,
                new_posture_score=current.posture_score,
                snapshot_id=current.id,
            )
            session.add(drift)
            drifts.append(drift)

            log.info(
                "Drift detected: %s/%s %s -> %s (%s)",
                fw,
                cid,
                previous.status,
                current.status,
                direction,
            )

        if drifts:
            session.flush()
            log.info("Detected %d compliance drift events", len(drifts))

        return drifts

    def correlate_changes(
        self,
        session: Session,
        drift: ComplianceDrift,
        window_hours: int = 2,
    ) -> list[ChangeEvent]:
        """Find change events temporally correlated with a drift.

        Queries ChangeEvent table for events within +/- window_hours of the
        drift detection time, filtering by resource types associated with
        findings for the drifted control.

        Args:
            session: SQLAlchemy session.
            drift: The ComplianceDrift to correlate.
            window_hours: Time window in hours (default 2).

        Returns:
            List of correlated ChangeEvent rows, ordered by temporal proximity.
        """
        detected_at = drift.detected_at
        if detected_at and detected_at.tzinfo is None:
            detected_at = detected_at.replace(tzinfo=timezone.utc)

        window = timedelta(hours=window_hours)
        start = detected_at - window
        end = detected_at + window

        # Get resource types from findings mapped to this control
        resource_types = (
            session.query(distinct(Finding.resource_type))
            .join(ControlResult, ControlResult.finding_id == Finding.id)
            .filter(
                ControlResult.framework == drift.framework,
                ControlResult.control_id == drift.control_id,
                Finding.resource_type.isnot(None),
            )
            .all()
        )
        rt_set = {row[0] for row in resource_types if row[0]}

        # Query change events in the time window
        query = (
            session.query(ChangeEvent)
            .filter(
                ChangeEvent.occurred_at >= start,
                ChangeEvent.occurred_at <= end,
            )
        )
        if rt_set:
            query = query.filter(ChangeEvent.resource_type.in_(rt_set))

        events = query.order_by(
            func.abs(
                func.julianday(ChangeEvent.occurred_at)
                - func.julianday(detected_at)
            )
        ).all()

        # Update drift record with correlated event IDs
        if events:
            drift.correlated_change_event_ids = [e.id for e in events]
            drift.correlation_confidence = min(
                1.0, len(events) * 0.3
            )
            session.flush()
            log.info(
                "Correlated %d change events with drift %s",
                len(events),
                drift.id,
            )

        return events

    def get_drifts(
        self,
        session: Session,
        framework: str | None = None,
        days: int = 30,
        direction: str | None = None,
    ) -> list[ComplianceDrift]:
        """Query drift history with filters.

        Args:
            session: SQLAlchemy session.
            framework: Optional framework filter.
            days: Look back this many days (default 30).
            direction: Filter by drift_direction (improved/degraded).

        Returns:
            List of ComplianceDrift rows.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = session.query(ComplianceDrift).filter(
            ComplianceDrift.detected_at >= cutoff,
        )

        if framework:
            query = query.filter(ComplianceDrift.framework == framework)
        if direction:
            query = query.filter(ComplianceDrift.drift_direction == direction)

        return query.order_by(ComplianceDrift.detected_at.desc()).all()
