"""Compensating control management.

Documents alternative controls when a primary control cannot be fully
implemented. Active compensating controls influence posture scoring.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
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

        status = kwargs.get("status")
        if status and status != "proposed":
            raise ValueError(
                f"New compensating controls must start in 'proposed' status, "
                f"not '{status}'. Use approve() to activate."
            )

        cc = CompensatingControl(**kwargs)
        session.add(cc)
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="compensating_control_created",
            entity_type="compensating_control",
            entity_id=str(cc.id),
            actor="system",
            metadata={
                "framework": cc.original_framework,
                "control_id": cc.original_control_id,
            },
        )

        log.info(
            "Created compensating control %s for %s/%s: %s",
            cc.id,
            cc.original_framework,
            cc.original_control_id,
            cc.title,
        )
        return cc

    def approve(self, session: Session, cc_id: str, approved_by: str) -> CompensatingControl:
        """Approve a compensating control. Must be in 'proposed' status."""
        cc = session.query(CompensatingControl).filter_by(id=cc_id).first()
        if not cc:
            raise ValueError(f"Compensating control not found: {cc_id}")
        if cc.status != "proposed":
            raise ValueError(f"Cannot approve from status '{cc.status}' — must be 'proposed'")
        cc.status = "approved"
        cc.approved_by = approved_by
        session.flush()
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
            query = query.filter(CompensatingControl.original_framework == framework)
        if status:
            query = query.filter(CompensatingControl.status == status)

        return query.order_by(CompensatingControl.created_at.desc()).all()

    def evaluate_effectiveness(
        self,
        session: Session,
        cc_id: str,
    ) -> dict:
        """Evaluate effectiveness of a compensating control based on evidence.

        STUB-013 fix: replaces the hardcoded ``{"score": 0.8}`` with actual
        evaluation logic.  Scoring factors:

        1. **Status weight** — approved/active controls score higher than proposed.
        2. **Evidence count** — more evidence references increase confidence.
        3. **Expiry proximity** — controls near expiry are penalised.
        4. **Review recency** — recently reviewed controls score higher.

        The resulting score (0-100) is written back to
        ``CompensatingControl.effectiveness_score``.

        Args:
            session: SQLAlchemy session.
            cc_id: CompensatingControl UUID.

        Returns:
            Dict with score, status, and breakdown of scoring factors.
        """
        cc = session.query(CompensatingControl).filter_by(id=cc_id).first()
        if not cc:
            raise ValueError(f"Compensating control not found: {cc_id}")

        now = datetime.now(timezone.utc)
        breakdown: dict[str, float] = {}

        # Factor 1: Status weight (0-25 points)
        status_weights = {
            "active": 25.0,
            "approved": 20.0,
            "proposed": 5.0,
            "expired": 0.0,
            "revoked": 0.0,
        }
        status_score = status_weights.get(cc.status, 0.0)
        breakdown["status"] = status_score

        # Factor 2: Evidence references (0-25 points)
        evidence_refs = cc.evidence_references or []
        evidence_count = len(evidence_refs)
        # 5 points per reference, capped at 25
        evidence_score = min(evidence_count * 5.0, 25.0)
        breakdown["evidence"] = evidence_score

        # Factor 3: Expiry proximity (0-25 points)
        if cc.expiry_date:
            expiry = ensure_aware(cc.expiry_date)
            days_until_expiry = (expiry - now).days
            if days_until_expiry <= 0:
                expiry_score = 0.0
            elif days_until_expiry <= 30:
                expiry_score = 5.0
            elif days_until_expiry <= 90:
                expiry_score = 15.0
            else:
                expiry_score = 25.0
        else:
            # No expiry set — assume indefinite validity, moderate score
            expiry_score = 20.0
        breakdown["expiry_proximity"] = expiry_score

        # Factor 4: Review recency (0-25 points)
        if cc.last_reviewed:
            last_reviewed = ensure_aware(cc.last_reviewed)
            days_since_review = (now - last_reviewed).days
            if days_since_review <= 30:
                review_score = 25.0
            elif days_since_review <= 90:
                review_score = 20.0
            elif days_since_review <= 180:
                review_score = 10.0
            else:
                review_score = 5.0
        else:
            # Never reviewed
            review_score = 0.0
        breakdown["review_recency"] = review_score

        total_score = sum(breakdown.values())
        total_score = min(max(total_score, 0.0), 100.0)

        # Determine qualitative status
        if total_score >= 70:
            effectiveness_status = "effective"
        elif total_score >= 40:
            effectiveness_status = "partially_effective"
        else:
            effectiveness_status = "ineffective"

        # Persist score back to the model
        cc.effectiveness_score = total_score
        session.flush()

        log.info(
            "Compensating control %s effectiveness: %.1f (%s)",
            cc_id[:8],
            total_score,
            effectiveness_status,
        )

        return {
            "cc_id": cc_id,
            "score": total_score,
            "status": effectiveness_status,
            "breakdown": breakdown,
        }
