"""Compliance drift detection.

Compares consecutive posture snapshots to identify status changes,
creates ComplianceDrift records, and correlates with ChangeEvents
for root cause analysis.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import distinct
from sqlalchemy.orm import Session

from warlock.db.models import (
    ChangeEvent,
    ComplianceDrift,
    ControlResult,
    Finding,
    PostureSnapshot,
)
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Status ordering for drift direction classification
_COMPLIANT_STATUSES = frozenset(
    {
        "compliant",
        "inherited_compliant",
        "risk_accepted",
    }
)


class DriftDetector:
    """Detects compliance status changes between posture snapshots."""

    def detect(
        self,
        session: Session,
        framework: str | None = None,
    ) -> list[ComplianceDrift]:
        """Compare the latest two snapshots per control using batch queries."""
        # Get the two most recent distinct snapshot dates
        date_query = (
            session.query(PostureSnapshot.snapshot_date)
            .distinct()
            .order_by(PostureSnapshot.snapshot_date.desc())
        )
        if framework:
            date_query = date_query.filter(PostureSnapshot.framework == framework)
        dates = [row[0] for row in date_query.limit(2).all()]

        if len(dates) < 2:
            return []

        current_date, previous_date = dates[0], dates[1]

        # Batch fetch current and previous snapshots
        current_snaps = {
            (s.framework, s.control_id): s
            for s in session.query(PostureSnapshot)
            .filter(PostureSnapshot.snapshot_date == current_date)
            .all()
        }
        previous_snaps = {
            (s.framework, s.control_id): s
            for s in session.query(PostureSnapshot)
            .filter(PostureSnapshot.snapshot_date == previous_date)
            .all()
        }

        # Batch check existing drift records for current snapshot
        existing_drift_keys = set()
        for d in (
            session.query(ComplianceDrift.framework, ComplianceDrift.control_id)
            .filter(ComplianceDrift.detected_at >= current_date)
            .all()
        ):
            existing_drift_keys.add((d.framework, d.control_id))

        drifts: list[ComplianceDrift] = []

        for key, current in current_snaps.items():
            previous = previous_snaps.get(key)
            if not previous or current.status == previous.status:
                continue
            if key in existing_drift_keys:
                continue

            fw, cid = key
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
                "Drift: %s/%s %s -> %s (%s)", fw, cid, previous.status, current.status, direction
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
        detected_at = ensure_aware(drift.detected_at)

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
        query = session.query(ChangeEvent).filter(
            ChangeEvent.occurred_at >= start,
            ChangeEvent.occurred_at <= end,
        )
        if rt_set:
            query = query.filter(ChangeEvent.resource_type.in_(rt_set))

        events = query.all()
        # Sort by temporal proximity in Python (avoids SQLite-specific func.julianday)
        events.sort(
            key=lambda e: abs(
                (ensure_aware(e.occurred_at) or e.occurred_at) - detected_at
            ).total_seconds()
        )

        # Update drift record with correlated event IDs
        if events:
            drift.correlated_change_event_ids = [e.id for e in events]
            drift.correlation_confidence = min(1.0, len(events) * 0.3)
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
