"""POA&M lifecycle management.

Handles auto-creation from non-compliant control results,
extension workflows with delay tracking, and overdue detection.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import and_
from sqlalchemy.orm import Session

from warlock.db.models import POAM, ControlResult, Finding

log = logging.getLogger(__name__)

# Terminal statuses that should not be considered "open"
_CLOSED_STATUSES = frozenset({"completed", "verified", "closed", "risk_accepted"})


class POAMManager:
    """Manages POA&M lifecycle: creation, extension, querying."""

    def auto_create_from_result(
        self,
        session: Session,
        control_result: ControlResult,
    ) -> POAM | None:
        """Create a draft POA&M if a non-compliant result lacks an open one.

        Checks for an existing open POA&M on the same (framework, control_id).
        If one exists, returns None. Otherwise creates a new draft.

        Args:
            session: SQLAlchemy session.
            control_result: The non-compliant ControlResult.

        Returns:
            Newly created POAM or None if one already exists.
        """
        if control_result.status not in ("non_compliant",):
            return None

        # Check for existing open POA&M
        existing = (
            session.query(POAM)
            .filter(
                POAM.framework == control_result.framework,
                POAM.control_id == control_result.control_id,
                ~POAM.status.in_(_CLOSED_STATUSES),
            )
            .first()
        )
        if existing:
            log.debug(
                "Open POA&M %s already exists for %s/%s",
                existing.id,
                control_result.framework,
                control_result.control_id,
            )
            return None

        # Build weakness description from finding + assertion failures
        weakness_parts: list[str] = []
        if control_result.finding_id:
            finding = session.get(Finding,control_result.finding_id)
            if finding:
                weakness_parts.append(finding.title)
        if control_result.assertion_findings:
            for af in control_result.assertion_findings:
                weakness_parts.append(str(af))

        weakness = "; ".join(weakness_parts) or (
            f"Non-compliant: {control_result.framework}/{control_result.control_id}"
        )

        poam = POAM(
            finding_id=control_result.finding_id,
            control_result_id=control_result.id,
            framework=control_result.framework,
            control_id=control_result.control_id,
            system_profile_id=control_result.system_profile_id,
            weakness_description=weakness,
            severity=control_result.severity,
            status="draft",
        )
        session.add(poam)
        session.flush()

        log.info(
            "Auto-created POA&M %s for %s/%s (severity=%s)",
            poam.id,
            poam.framework,
            poam.control_id,
            poam.severity,
        )
        return poam

    def extend(
        self,
        session: Session,
        poam_id: str,
        justification: str,
        new_date: datetime,
        approved_by: str,
    ) -> POAM:
        """Extend a POA&M's scheduled completion date.

        Increments delay_count, appends justification to the audit trail.

        Args:
            session: SQLAlchemy session.
            poam_id: ID of the POA&M to extend.
            justification: Reason for the extension.
            new_date: New scheduled completion date.
            approved_by: Who approved the extension.

        Returns:
            Updated POAM.

        Raises:
            ValueError: If POA&M not found or in a terminal status.
        """
        poam = session.get(POAM,poam_id)
        if not poam:
            raise ValueError(f"POA&M not found: {poam_id}")
        if poam.status in _CLOSED_STATUSES:
            raise ValueError(
                f"Cannot extend POA&M {poam_id} in status '{poam.status}'"
            )

        poam.delay_count = (poam.delay_count or 0) + 1

        justifications = list(poam.delay_justifications or [])
        justifications.append({
            "date": datetime.now(timezone.utc).isoformat(),
            "justification": justification,
            "approved_by": approved_by,
        })
        poam.delay_justifications = justifications
        poam.scheduled_completion = new_date
        poam.updated_by = approved_by

        session.flush()
        log.info(
            "Extended POA&M %s to %s (delay #%d, approved by %s)",
            poam_id,
            new_date.isoformat(),
            poam.delay_count,
            approved_by,
        )
        return poam

    def list_poams(
        self,
        session: Session,
        framework: str | None = None,
        status: str | None = None,
        overdue: bool = False,
    ) -> list[POAM]:
        """List POA&Ms with optional filters.

        Args:
            session: SQLAlchemy session.
            framework: Filter by framework.
            status: Filter by status.
            overdue: If True, only return overdue POA&Ms.

        Returns:
            List of matching POAM rows.
        """
        query = session.query(POAM)

        if framework:
            query = query.filter(POAM.framework == framework)
        if status:
            query = query.filter(POAM.status == status)
        if overdue:
            now = datetime.now(timezone.utc)
            query = query.filter(
                POAM.scheduled_completion < now,
                ~POAM.status.in_(_CLOSED_STATUSES),
            )

        return query.order_by(POAM.scheduled_completion).all()

    def get_overdue(self, session: Session) -> list[POAM]:
        """Return all POA&Ms past their scheduled completion that are still open.

        Returns:
            List of overdue POAM rows, ordered by scheduled completion.
        """
        now = datetime.now(timezone.utc)
        return (
            session.query(POAM)
            .filter(
                POAM.scheduled_completion < now,
                POAM.scheduled_completion.isnot(None),
                ~POAM.status.in_(_CLOSED_STATUSES),
            )
            .order_by(POAM.scheduled_completion)
            .all()
        )
