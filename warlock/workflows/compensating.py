"""Compensating control management.

Documents alternative controls when a primary control cannot be fully
implemented. Active compensating controls influence posture scoring.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.models import CompensatingControl
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

_ACTIVE_STATUSES = frozenset({"active"})


class CompensatingControlManager:
    """CRUD and query operations for compensating controls."""

    def create(self, session: Session, **kwargs) -> CompensatingControl:
        """Create a new compensating control.

        Required kwargs: original_framework, original_control_id, title,
        description. Optional: poam_id, system_profile_id,
        implementation_details, evidence_references, expiry_date,
        review_frequency, created_by, status.

        Returns:
            Newly created CompensatingControl.
        """
        # Validate required fields
        for required_field in ("original_framework", "original_control_id", "title"):
            if not kwargs.get(required_field):
                raise ValueError(
                    f"Missing required field for compensating control: {required_field}"
                )

        cc = CompensatingControl(**kwargs)
        session.add(cc)
        session.flush()

        log.info(
            "Created compensating control %s for %s/%s: %s",
            cc.id,
            cc.original_framework,
            cc.original_control_id,
            cc.title,
        )
        return cc

    def check_for_control(
        self,
        session: Session,
        framework: str,
        control_id: str,
    ) -> CompensatingControl | None:
        """Return active compensating control for the given control, if any.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            control_id: Control identifier.

        Returns:
            Active CompensatingControl or None.
        """
        now = datetime.now(timezone.utc)
        cc = (
            session.query(CompensatingControl)
            .filter(
                CompensatingControl.original_framework == framework,
                CompensatingControl.original_control_id == control_id,
                CompensatingControl.status.in_(_ACTIVE_STATUSES),
            )
            .first()
        )

        # Check expiry — an active control past its expiry is not valid
        # W-4: ensure_aware before comparing expiry_date
        if cc and cc.expiry_date and ensure_aware(cc.expiry_date) < now:
            log.info(
                "Compensating control %s expired at %s, skipping",
                cc.id,
                cc.expiry_date.isoformat(),
            )
            return None

        return cc

    def list_controls(
        self,
        session: Session,
        framework: str | None = None,
        status: str | None = None,
    ) -> list[CompensatingControl]:
        """List compensating controls with optional filters.

        Args:
            session: SQLAlchemy session.
            framework: Filter by original_framework.
            status: Filter by status.

        Returns:
            List of matching CompensatingControl rows.
        """
        query = session.query(CompensatingControl)

        if framework:
            query = query.filter(
                CompensatingControl.original_framework == framework
            )
        if status:
            query = query.filter(CompensatingControl.status == status)

        return query.order_by(CompensatingControl.created_at.desc()).all()
