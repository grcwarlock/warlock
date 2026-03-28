"""GAP-043: Recurring evidence collection scheduling.

Uses the EvidenceRequest model to create, track, and fulfill
scheduled evidence collection tasks tied to controls.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import EvidenceRequest, _uuid
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


class EvidenceScheduler:
    """Schedule recurring evidence collection tasks."""

    def __init__(self, session: Session):
        self.session = session

    def create_schedule(
        self,
        control_id: str,
        framework: str,
        frequency_days: int,
        collector_type: str,
        description: str,
        engagement_id: str = "",
        auditor_id: str = "",
    ) -> EvidenceRequest:
        """Create a recurring evidence collection schedule.

        Creates an EvidenceRequest with status ``requested`` and a
        ``due_date`` set to now + ``frequency_days``.

        Args:
            control_id: The control requiring evidence.
            framework: Framework the control belongs to.
            frequency_days: How often evidence should be collected.
            collector_type: Type of collection (e.g. "automated", "manual").
            description: Human-readable description of what to collect.
            engagement_id: Audit engagement ID (required by model FK).
            auditor_id: Auditor requesting evidence (required by model FK).

        Returns:
            The newly created EvidenceRequest.
        """
        now = datetime.now(timezone.utc)
        due_date = now + timedelta(days=frequency_days)

        request = EvidenceRequest(
            id=_uuid(),
            engagement_id=engagement_id,
            auditor_id=auditor_id,
            framework=framework,
            control_id=control_id,
            description=description,
            status="requested",
        )
        # Store scheduling metadata in fulfillment_notes as JSON-compatible string
        request.fulfillment_notes = (
            f"collector_type={collector_type};"
            f"frequency_days={frequency_days};"
            f"due_date={due_date.isoformat()}"
        )
        self.session.add(request)
        self.session.flush()

        audit = AuditTrail(self.session)
        audit.record(
            action="evidence_schedule_created",
            entity_type="evidence_request",
            entity_id=str(request.id),
            actor="system",
            metadata={
                "control_id": control_id,
                "framework": framework,
                "frequency_days": frequency_days,
                "collector_type": collector_type,
                "due_date": due_date.isoformat(),
            },
        )

        log.info(
            "Evidence schedule created: %s for %s/%s (every %d days, due %s)",
            request.id,
            framework,
            control_id,
            frequency_days,
            due_date.isoformat(),
        )
        return request

    def get_due(self) -> list[EvidenceRequest]:
        """Return evidence requests that are due for collection.

        Parses the due_date from fulfillment_notes and compares against
        the current time. Only returns requests with status ``requested``.

        Returns:
            List of EvidenceRequest rows that are past their due date.
        """
        now = datetime.now(timezone.utc)
        requests = (
            self.session.query(EvidenceRequest).filter(EvidenceRequest.status == "requested").all()
        )

        due: list[EvidenceRequest] = []
        for req in requests:
            due_date = self._parse_due_date(req)
            if due_date and ensure_aware(due_date) <= now:
                due.append(req)

        return due

    def mark_collected(
        self,
        request_id: str,
        evidence_hash: str,
        collected_by: str,
    ) -> EvidenceRequest:
        """Mark an evidence request as fulfilled.

        Args:
            request_id: ID of the evidence request.
            evidence_hash: SHA-256 hash of collected evidence.
            collected_by: Who collected the evidence.

        Returns:
            Updated EvidenceRequest.

        Raises:
            ValueError: If request not found or already fulfilled.
        """
        request = self.session.get(EvidenceRequest, request_id)
        if not request:
            raise ValueError(f"Evidence request not found: {request_id}")
        if request.status == "fulfilled":
            raise ValueError(f"Evidence request {request_id} is already fulfilled")

        now = datetime.now(timezone.utc)
        request.status = "fulfilled"
        request.fulfilled_by = collected_by
        request.fulfilled_at = now
        self.session.flush()

        audit = AuditTrail(self.session)
        audit.record(
            action="evidence_collected",
            entity_type="evidence_request",
            entity_id=str(request.id),
            actor=collected_by,
            evidence_sha256=evidence_hash,
            metadata={
                "collected_by": collected_by,
                "evidence_hash": evidence_hash,
            },
        )

        log.info(
            "Evidence collected for request %s by %s (hash=%s)",
            request_id,
            collected_by,
            evidence_hash[:16],
        )
        return request

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_due_date(request: EvidenceRequest) -> datetime | None:
        """Extract due_date from fulfillment_notes metadata string."""
        notes = request.fulfillment_notes or ""
        for part in notes.split(";"):
            if part.startswith("due_date="):
                try:
                    return datetime.fromisoformat(part.split("=", 1)[1])
                except (ValueError, IndexError):
                    return None
        return None
