"""End-to-end audit program lifecycle management.

Item 78: Full audit program lifecycle with state machine:
plan -> scope -> fieldwork -> draft_report -> management_response ->
final_report -> follow_up

Uses audit_engagements as the backing model, with program phase
tracked in the engagement status field extended with program-specific
states stored in audit trail metadata.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import AuditEngagement
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Valid program phases and allowed transitions
PROGRAM_PHASES = (
    "plan",
    "scope",
    "fieldwork",
    "draft_report",
    "management_response",
    "final_report",
    "follow_up",
    "completed",
)

_TRANSITIONS: dict[str, list[str]] = {
    "plan": ["scope"],
    "scope": ["fieldwork", "plan"],
    "fieldwork": ["draft_report", "scope"],
    "draft_report": ["management_response"],
    "management_response": ["final_report", "draft_report"],
    "final_report": ["follow_up"],
    "follow_up": ["completed"],
    "completed": [],
}


class AuditProgramManager:
    """Manages the full audit program lifecycle."""

    @staticmethod
    def _resolve_engagement(session: Session, engagement_id: str) -> AuditEngagement:
        """Resolve engagement by full or partial UUID."""
        eng = session.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
        if eng:
            return eng
        # Try prefix match
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id.startswith(engagement_id))
            .first()
        )
        if eng:
            return eng
        raise ValueError(f"Engagement not found: {engagement_id}")

    def get_program_phase(self, session: Session, engagement_id: str) -> str:
        """Get the current program phase for an engagement.

        Reads the latest audit_program_advanced entry, falling back to 'plan'.
        """
        from warlock.db.models import AuditEntry

        entry = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "audit_program",
                AuditEntry.entity_id == engagement_id,
                AuditEntry.action == "audit_program_advanced",
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )

        if entry and entry.extra:
            return entry.extra.get("to_phase", "plan")
        return "plan"

    def get_status(self, session: Session, engagement_id: str) -> dict:
        """Get full program status for an engagement."""
        eng = self._resolve_engagement(session, engagement_id)

        phase = self.get_program_phase(session, engagement_id)

        # Count phase history
        from warlock.db.models import AuditEntry

        history = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.entity_type == "audit_program",
                AuditEntry.entity_id == engagement_id,
            )
            .order_by(AuditEntry.created_at.asc())
            .all()
        )

        phase_history = []
        for h in history:
            meta = h.extra or {}
            phase_history.append(
                {
                    "from": meta.get("from_phase", ""),
                    "to": meta.get("to_phase", ""),
                    "actor": h.actor or "",
                    "timestamp": ensure_aware(h.created_at).isoformat() if h.created_at else "",
                    "notes": meta.get("notes", ""),
                }
            )

        return {
            "engagement_id": eng.id,
            "engagement_name": eng.name,
            "framework": eng.framework,
            "current_phase": phase,
            "allowed_transitions": _TRANSITIONS.get(phase, []),
            "period_start": eng.period_start.isoformat() if eng.period_start else "",
            "period_end": eng.period_end.isoformat() if eng.period_end else "",
            "auditor": eng.auditor_name or "",
            "firm": eng.auditor_firm or "",
            "phase_history": phase_history,
        }

    def advance(
        self,
        session: Session,
        engagement_id: str,
        *,
        actor: str = "system",
        notes: str = "",
    ) -> dict:
        """Advance the engagement to the next phase in sequence.

        Raises ValueError if the engagement is already completed.
        """
        self._resolve_engagement(session, engagement_id)  # validates existence

        current = self.get_program_phase(session, engagement_id)
        allowed = _TRANSITIONS.get(current, [])

        if not allowed:
            raise ValueError(
                f"Engagement {engagement_id} is in phase '{current}' "
                "which has no further transitions."
            )

        # Advance to first allowed (sequential progression)
        next_phase = allowed[0]
        return self.transition(
            session,
            engagement_id,
            to_phase=next_phase,
            actor=actor,
            notes=notes,
        )

    def transition(
        self,
        session: Session,
        engagement_id: str,
        *,
        to_phase: str,
        actor: str = "system",
        notes: str = "",
    ) -> dict:
        """Transition an engagement to a specific phase.

        Validates the transition is allowed from the current phase.
        """
        eng = self._resolve_engagement(session, engagement_id)

        if to_phase not in PROGRAM_PHASES:
            raise ValueError(
                f"Invalid phase '{to_phase}'. Valid phases: {', '.join(PROGRAM_PHASES)}"
            )

        current = self.get_program_phase(session, engagement_id)
        allowed = _TRANSITIONS.get(current, [])

        if to_phase not in allowed:
            raise ValueError(
                f"Cannot transition from '{current}' to '{to_phase}'. "
                f"Allowed: {', '.join(allowed) if allowed else 'none (completed)'}"
            )

        audit = AuditTrail(session)
        audit.record(
            action="audit_program_advanced",
            entity_type="audit_program",
            entity_id=engagement_id,
            actor=actor,
            metadata={
                "from_phase": current,
                "to_phase": to_phase,
                "notes": notes,
            },
        )

        # Update engagement status if completing
        if to_phase == "completed":
            eng.status = "completed"
            eng.completed_at = datetime.now(timezone.utc)

        log.info(
            "Audit program %s advanced: %s -> %s (by %s)",
            engagement_id,
            current,
            to_phase,
            actor,
        )

        return {
            "engagement_id": engagement_id,
            "from_phase": current,
            "to_phase": to_phase,
            "notes": notes,
        }

    def list_programs(self, session: Session) -> list[dict]:
        """List all audit engagements with their program phase."""
        engagements = (
            session.query(AuditEngagement).order_by(AuditEngagement.created_at.desc()).all()
        )

        programs = []
        for eng in engagements:
            phase = self.get_program_phase(session, eng.id)
            programs.append(
                {
                    "id": eng.id,
                    "name": eng.name,
                    "framework": eng.framework,
                    "phase": phase,
                    "status": eng.status,
                    "period_start": eng.period_start.isoformat() if eng.period_start else "",
                    "period_end": eng.period_end.isoformat() if eng.period_end else "",
                    "auditor": eng.auditor_name or "",
                }
            )

        return programs
