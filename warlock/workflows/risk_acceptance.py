"""Risk acceptance workflow.

Manages formal risk acceptance with AO-level approval, expiry tracking,
and automatic detection of expired acceptances.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import ControlResult, RiskAcceptance
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

_ACTIVE_STATUSES = frozenset({"active"})
_TERMINAL_STATUSES = frozenset({"expired", "revoked"})

# Severity ordering for severity_change trigger evaluation
_SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "moderate": 1,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


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
        status = kwargs.get("status")
        if status and status not in ("requested", "reviewed"):
            raise ValueError(
                f"New risk acceptances must start in 'requested' or 'reviewed' status, "
                f"not '{status}'. Use approve() for status transitions."
            )

        ra = RiskAcceptance(**kwargs)
        session.add(ra)
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="risk_acceptance_created",
            entity_type="risk_acceptance",
            entity_id=str(ra.id),
            actor=kwargs.get("requested_by", "system"),
            metadata={
                "framework": ra.framework,
                "control_id": ra.control_id,
                "status": ra.status,
            },
        )

        log.info(
            "Created risk acceptance %s for %s/%s (risk=%s, requested_by=%s)",
            ra.id,
            ra.framework,
            ra.control_id,
            ra.risk_level,
            ra.requested_by,
        )
        return ra

    def approve(self, session: Session, ra_id: str, approved_by: str) -> RiskAcceptance:
        """Approve a risk acceptance. Must be in 'reviewed' status."""
        ra = session.query(RiskAcceptance).filter_by(id=ra_id).first()
        if not ra:
            raise ValueError(f"Risk acceptance not found: {ra_id}")
        if ra.status != "reviewed":
            raise ValueError(f"Cannot approve from status '{ra.status}' — must be 'reviewed'")
        ra.status = "approved"
        ra.approved_by = approved_by
        session.flush()
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

    def evaluate_triggers(
        self,
        session: Session,
    ) -> list[dict[str, Any]]:
        """Scan active risk acceptances and check auto re-evaluation triggers.

        For each active (non-expired) risk acceptance with auto_reeval_triggers
        configured, evaluates:

        - **severity_change**: If the latest ControlResult for the accepted
          control has a severity higher than the acceptance's risk_level,
          the acceptance needs re-evaluation.
        - **new_finding**: If any ControlResult for the accepted control
          was assessed after the acceptance was approved (or created),
          the acceptance needs re-evaluation.
        - **time_elapsed**: If more than ``days`` have passed since the
          acceptance was approved (or created), it needs periodic review.
          Distinct from expiry — this is a mid-lifecycle check.

        Returns:
            List of dicts describing acceptances needing re-evaluation,
            each containing ``acceptance_id``, ``framework``, ``control_id``,
            ``triggered_by`` (list of trigger names), and ``details``.
        """
        now = datetime.now(timezone.utc)

        actives = (
            session.query(RiskAcceptance)
            .filter(
                RiskAcceptance.status.in_(_ACTIVE_STATUSES),
                RiskAcceptance.expiry_date > now,
            )
            .all()
        )

        results: list[dict[str, Any]] = []

        for ra in actives:
            triggers = ra.auto_reeval_triggers or {}
            if not triggers:
                continue

            triggered_by: list[str] = []
            details: dict[str, Any] = {}
            baseline_dt = ensure_aware(ra.approved_at) or ensure_aware(ra.created_at) or now

            # --- severity_change trigger ---
            if triggers.get("severity_change"):
                latest_result = (
                    session.query(ControlResult)
                    .filter(
                        ControlResult.framework == ra.framework,
                        ControlResult.control_id == ra.control_id,
                    )
                    .order_by(ControlResult.assessed_at.desc())
                    .first()
                )
                if latest_result and latest_result.severity:
                    accepted_level = _SEVERITY_ORDER.get((ra.risk_level or "").lower(), 0)
                    current_level = _SEVERITY_ORDER.get(latest_result.severity.lower(), 0)
                    if current_level > accepted_level:
                        triggered_by.append("severity_change")
                        details["severity_change"] = {
                            "accepted_risk_level": ra.risk_level,
                            "current_severity": latest_result.severity,
                        }

            # --- new_finding trigger ---
            if triggers.get("new_finding"):
                new_result = (
                    session.query(ControlResult)
                    .filter(
                        ControlResult.framework == ra.framework,
                        ControlResult.control_id == ra.control_id,
                        ControlResult.assessed_at > baseline_dt,
                    )
                    .first()
                )
                if new_result:
                    triggered_by.append("new_finding")
                    details["new_finding"] = {
                        "finding_assessed_at": (
                            new_result.assessed_at.isoformat() if new_result.assessed_at else None
                        ),
                    }

            # --- time_elapsed trigger ---
            time_elapsed_cfg = triggers.get("time_elapsed")
            if time_elapsed_cfg:
                elapsed_days = int(
                    time_elapsed_cfg
                    if isinstance(time_elapsed_cfg, (int, float))
                    else time_elapsed_cfg.get("days", 90)
                    if isinstance(time_elapsed_cfg, dict)
                    else 90
                )
                days_since = (now - baseline_dt).total_seconds() / 86400.0
                if days_since >= elapsed_days:
                    triggered_by.append("time_elapsed")
                    details["time_elapsed"] = {
                        "threshold_days": elapsed_days,
                        "actual_days": round(days_since, 1),
                    }

            if triggered_by:
                results.append(
                    {
                        "acceptance_id": ra.id,
                        "framework": ra.framework,
                        "control_id": ra.control_id,
                        "risk_level": ra.risk_level,
                        "triggered_by": triggered_by,
                        "details": details,
                    }
                )
                log.warning(
                    "Risk acceptance %s (%s/%s) triggered for re-evaluation: %s",
                    ra.id,
                    ra.framework,
                    ra.control_id,
                    ", ".join(triggered_by),
                )

        return results
