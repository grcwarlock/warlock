"""Risk acceptance workflow.

Manages formal risk acceptance with AO-level approval, expiry tracking,
and automatic detection of expired acceptances.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from warlock.db.models import RiskAcceptance
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

_ACTIVE_STATUSES = frozenset({"active"})
_TERMINAL_STATUSES = frozenset({"expired", "revoked"})


class RiskAcceptanceManager:
    """Manages the risk acceptance lifecycle."""

    def create(self, session: Session, **kwargs) -> RiskAcceptance:
        """Create a new risk acceptance request.

        Required kwargs: framework, control_id, risk_description,
        risk_level, requested_by, expiry_date. Optional: poam_id,
        system_profile_id, residual_risk_level, conditions,
        auto_reeval_triggers, status.

        Returns:
            Newly created RiskAcceptance.
        """
        ra = RiskAcceptance(**kwargs)
        session.add(ra)
        session.flush()

        log.info(
            "Created risk acceptance %s for %s/%s (risk=%s, requested_by=%s)",
            ra.id,
            ra.framework,
            ra.control_id,
            ra.risk_level,
            ra.requested_by,
        )
        return ra

    def check_for_control(
        self,
        session: Session,
        framework: str,
        control_id: str,
    ) -> RiskAcceptance | None:
        """Return active risk acceptance for the given control, if any.

        Only returns acceptances that are active and not expired.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier.
            control_id: Control identifier.

        Returns:
            Active RiskAcceptance or None.
        """
        now = datetime.now(timezone.utc)
        ra = (
            session.query(RiskAcceptance)
            .filter(
                RiskAcceptance.framework == framework,
                RiskAcceptance.control_id == control_id,
                RiskAcceptance.status.in_(_ACTIVE_STATUSES),
                RiskAcceptance.expiry_date > now,
            )
            .first()
        )
        # W-4: ensure_aware before comparing expiry_date
        if ra and ra.expiry_date and ensure_aware(ra.expiry_date) <= now:
            return None
        return ra

    def check_expired(self, session: Session) -> list[RiskAcceptance]:
        """Find active risk acceptances that have passed their expiry date.

        Used by the scheduler to detect and transition expired acceptances.

        Returns:
            List of expired RiskAcceptance rows still in active status.
        """
        now = datetime.now(timezone.utc)
        return (
            session.query(RiskAcceptance)
            .filter(
                RiskAcceptance.status.in_(_ACTIVE_STATUSES),
                RiskAcceptance.expiry_date <= now,
            )
            .order_by(RiskAcceptance.expiry_date)
            .all()
        )

    def list_acceptances(
        self,
        session: Session,
        framework: str | None = None,
        status: str | None = None,
        expiring_days: int | None = None,
    ) -> list[RiskAcceptance]:
        """List risk acceptances with optional filters.

        Args:
            session: SQLAlchemy session.
            framework: Filter by framework.
            status: Filter by status.
            expiring_days: If set, only return active acceptances expiring
                within this many days.

        Returns:
            List of matching RiskAcceptance rows.
        """
        query = session.query(RiskAcceptance)

        if framework:
            query = query.filter(RiskAcceptance.framework == framework)
        if status:
            query = query.filter(RiskAcceptance.status == status)
        if expiring_days is not None:
            now = datetime.now(timezone.utc)
            cutoff = now + timedelta(days=expiring_days)
            query = query.filter(
                RiskAcceptance.status.in_(_ACTIVE_STATUSES),
                RiskAcceptance.expiry_date <= cutoff,
                RiskAcceptance.expiry_date > now,
            )

        return query.order_by(RiskAcceptance.expiry_date).all()
