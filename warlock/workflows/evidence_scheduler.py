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

    # ------------------------------------------------------------------
    # Item 76: Evidence sufficiency scoring
    # ------------------------------------------------------------------

    def score_sufficiency(
        self,
        framework: str | None = None,
    ) -> list[dict]:
        """Score evidence sufficiency per control.

        Scores on three dimensions (each 0-100):
        - relevance: Does evidence map to the right control? (has finding_id)
        - completeness: Are all sub-requirements assessed? (not not_assessed)
        - recency: Is the evidence fresh? (assessed within threshold)

        Overall score = weighted average (relevance 40%, completeness 30%, recency 30%).
        """
        from warlock.db.models import ControlResult

        q = self.session.query(ControlResult)
        if framework:
            q = q.filter(ControlResult.framework == framework)

        results = q.all()
        now = datetime.now(timezone.utc)

        # Group by control
        by_control: dict[str, list] = {}
        for r in results:
            key = f"{r.framework}:{r.control_id}"
            by_control.setdefault(key, []).append(r)

        scores = []
        for key, control_results in sorted(by_control.items()):
            fw, cid = key.split(":", 1)

            # Relevance: proportion with a finding_id (evidence link)
            linked = sum(1 for r in control_results if r.finding_id)
            relevance = (linked / len(control_results) * 100) if control_results else 0

            # Completeness: proportion assessed (not not_assessed)
            assessed = sum(1 for r in control_results if r.status != "not_assessed")
            completeness = (assessed / len(control_results) * 100) if control_results else 0

            # Recency: score based on freshest assessment
            freshest = None
            for r in control_results:
                if r.assessed_at:
                    dt = ensure_aware(r.assessed_at)
                    if freshest is None or dt > freshest:
                        freshest = dt

            threshold_days = 30
            if freshest:
                age_days = (now - freshest).days
                if age_days <= threshold_days:
                    recency = 100.0
                elif age_days <= threshold_days * 2:
                    recency = 50.0
                else:
                    recency = max(0.0, 100.0 - (age_days / threshold_days) * 25)
            else:
                recency = 0.0

            overall = relevance * 0.4 + completeness * 0.3 + recency * 0.3

            scores.append(
                {
                    "framework": fw,
                    "control_id": cid,
                    "relevance": round(relevance, 1),
                    "completeness": round(completeness, 1),
                    "recency": round(recency, 1),
                    "overall": round(overall, 1),
                    "result_count": len(control_results),
                }
            )

        return sorted(scores, key=lambda s: s["overall"])

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
