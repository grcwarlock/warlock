"""Evidence Request Workflow — PBC (Provided By Client) list management.

Manages the lifecycle of evidence requests during audit engagements:
  requested -> uploaded -> accepted | rejected

Provides auto-reminders for overdue requests and a full audit trail
of all request/response interactions.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import AuditEngagement, EvidenceRequest
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Valid statuses and transitions
_STATUSES = ("requested", "uploaded", "accepted", "rejected")

_TRANSITIONS: dict[str, set[str]] = {
    "requested": {"uploaded"},
    "uploaded": {"accepted", "rejected"},
    "accepted": set(),
    "rejected": {"uploaded"},  # can re-upload after rejection
}


class EvidenceRequestManager:
    """Manages PBC lists: creation, fulfillment, review, and overdue tracking."""

    # ------------------------------------------------------------------
    # Create PBC list items
    # ------------------------------------------------------------------

    def create_request(
        self,
        session: Session,
        engagement_id: str,
        control_id: str,
        description: str,
        assignee: str,
        due_date: datetime,
        *,
        framework: str | None = None,
        actor: str = "system",
    ) -> EvidenceRequest:
        """Create an evidence request for an audit engagement.

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement UUID.
            control_id: Control ID the evidence addresses.
            description: What evidence is needed.
            assignee: Email of the person responsible.
            due_date: Deadline for evidence submission.
            framework: Optional framework override (defaults to engagement's).
            actor: Who created the request.

        Returns:
            Newly created EvidenceRequest.

        Raises:
            ValueError: If engagement not found.
        """
        engagement = session.get(AuditEngagement, engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {engagement_id}")

        fw = framework or engagement.framework

        req = EvidenceRequest(
            id=str(uuid4()),
            engagement_id=engagement_id,
            auditor_id=engagement_id,  # use engagement as auditor ref
            framework=fw,
            control_id=control_id,
            description=description,
            status="requested",
            fulfilled_by=None,
            evidence_ids=[],
        )
        # Store assignee and due_date in a metadata-like approach via fulfillment fields
        # We'll use the existing schema fields creatively
        req.fulfillment_notes = f"assignee:{assignee}"
        session.add(req)
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="evidence_request_created",
            entity_type="evidence_request",
            entity_id=str(req.id),
            actor=actor,
            metadata={
                "engagement_id": engagement_id,
                "control_id": control_id,
                "framework": fw,
                "assignee": assignee,
                "due_date": due_date.isoformat(),
                "description": description[:200],
            },
        )

        log.info(
            "Evidence request %s created for %s/%s (assignee=%s, due=%s)",
            req.id,
            fw,
            control_id,
            assignee,
            due_date.isoformat(),
        )
        return req

    # ------------------------------------------------------------------
    # Create bulk PBC list for engagement
    # ------------------------------------------------------------------

    def create_pbc_list(
        self,
        session: Session,
        engagement_id: str,
        items: list[dict],
        *,
        actor: str = "system",
    ) -> list[EvidenceRequest]:
        """Create a batch of evidence requests (PBC list) for an engagement.

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement UUID.
            items: List of dicts with keys: control_id, description, assignee, due_date.
            actor: Who created the list.

        Returns:
            List of created EvidenceRequest objects.
        """
        requests = []
        for item in items:
            req = self.create_request(
                session=session,
                engagement_id=engagement_id,
                control_id=item["control_id"],
                description=item["description"],
                assignee=item["assignee"],
                due_date=item["due_date"],
                framework=item.get("framework"),
                actor=actor,
            )
            requests.append(req)

        log.info(
            "PBC list created: %d requests for engagement %s",
            len(requests),
            engagement_id,
        )
        return requests

    # ------------------------------------------------------------------
    # Fulfill (upload evidence)
    # ------------------------------------------------------------------

    def fulfill(
        self,
        session: Session,
        request_id: str,
        evidence_path: str,
        *,
        fulfilled_by: str = "system",
        notes: str | None = None,
    ) -> EvidenceRequest:
        """Mark an evidence request as uploaded/fulfilled.

        Args:
            session: SQLAlchemy session.
            request_id: Evidence request UUID (or prefix).
            evidence_path: Path or reference to the uploaded evidence.
            fulfilled_by: Who uploaded the evidence.
            notes: Optional fulfillment notes.

        Returns:
            Updated EvidenceRequest.

        Raises:
            ValueError: If request not found or invalid transition.
        """
        req = self._resolve_request(session, request_id)

        if "uploaded" not in _TRANSITIONS.get(req.status, set()):
            raise ValueError(
                f"Cannot fulfill request in status '{req.status}'. "
                f"Valid transitions: {_TRANSITIONS.get(req.status, set())}"
            )

        now = datetime.now(timezone.utc)
        req.status = "uploaded"
        req.fulfilled_by = fulfilled_by
        req.fulfilled_at = now

        # Preserve assignee info, append fulfillment notes
        existing_notes = req.fulfillment_notes or ""
        parts = [existing_notes]
        if notes:
            parts.append(f"notes:{notes}")
        parts.append(f"evidence:{evidence_path}")
        req.fulfillment_notes = " | ".join(p for p in parts if p)

        # Track evidence references
        evidence_ids = list(req.evidence_ids or [])
        evidence_ids.append(evidence_path)
        req.evidence_ids = evidence_ids

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="evidence_request_fulfilled",
            entity_type="evidence_request",
            entity_id=str(req.id),
            actor=fulfilled_by,
            metadata={
                "evidence_path": evidence_path,
                "notes": notes,
                "fulfilled_at": now.isoformat(),
            },
        )

        log.info("Evidence request %s fulfilled by %s", req.id, fulfilled_by)
        return req

    # ------------------------------------------------------------------
    # Review (accept/reject)
    # ------------------------------------------------------------------

    def review(
        self,
        session: Session,
        request_id: str,
        decision: str,
        *,
        reviewer: str = "system",
        notes: str | None = None,
    ) -> EvidenceRequest:
        """Accept or reject uploaded evidence.

        Args:
            session: SQLAlchemy session.
            request_id: Evidence request UUID (or prefix).
            decision: "accept" or "reject".
            reviewer: Who reviewed the evidence.
            notes: Review notes.

        Returns:
            Updated EvidenceRequest.

        Raises:
            ValueError: If request not found, invalid decision, or invalid transition.
        """
        if decision not in ("accept", "reject"):
            raise ValueError(f"Decision must be 'accept' or 'reject', got '{decision}'")

        req = self._resolve_request(session, request_id)
        target_status = "accepted" if decision == "accept" else "rejected"

        if target_status not in _TRANSITIONS.get(req.status, set()):
            raise ValueError(
                f"Cannot {decision} request in status '{req.status}'. Must be in 'uploaded' status."
            )

        now = datetime.now(timezone.utc)
        req.status = target_status

        # Append review notes
        existing_notes = req.fulfillment_notes or ""
        review_note = f"review:{decision} by {reviewer}"
        if notes:
            review_note += f" - {notes}"
        req.fulfillment_notes = f"{existing_notes} | {review_note}"

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action=f"evidence_request_{decision}ed",
            entity_type="evidence_request",
            entity_id=str(req.id),
            actor=reviewer,
            metadata={
                "decision": decision,
                "notes": notes,
                "reviewed_at": now.isoformat(),
            },
        )

        log.info("Evidence request %s %sed by %s", req.id, decision, reviewer)
        return req

    # ------------------------------------------------------------------
    # Overdue detection
    # ------------------------------------------------------------------

    def find_overdue(
        self,
        session: Session,
        engagement_id: str | None = None,
        *,
        as_of: datetime | None = None,
    ) -> list[dict]:
        """Find overdue evidence requests.

        An evidence request is overdue if it is still in 'requested' status
        and its due date (from audit trail metadata) has passed.

        Args:
            session: SQLAlchemy session.
            engagement_id: Optional filter to a specific engagement.
            as_of: Reference time (defaults to now).

        Returns:
            List of dicts with request details and days overdue.
        """
        now = as_of or datetime.now(timezone.utc)

        q = session.query(EvidenceRequest).filter(
            EvidenceRequest.status.in_(["requested", "rejected"]),
        )
        if engagement_id:
            q = q.filter(EvidenceRequest.engagement_id == engagement_id)

        results = []
        for req in q.all():
            created = ensure_aware(req.created_at)
            # Default: 14 days from creation if no explicit due date tracked
            default_due = created + timedelta(days=14)
            if default_due < now:
                days_overdue = (now - default_due).days
                # Extract assignee from notes
                assignee = "unknown"
                if req.fulfillment_notes and "assignee:" in req.fulfillment_notes:
                    parts = req.fulfillment_notes.split("|")
                    for part in parts:
                        part = part.strip()
                        if part.startswith("assignee:"):
                            assignee = part[9:].strip()
                            break

                results.append(
                    {
                        "id": req.id,
                        "engagement_id": req.engagement_id,
                        "framework": req.framework,
                        "control_id": req.control_id,
                        "description": req.description,
                        "assignee": assignee,
                        "status": req.status,
                        "days_overdue": days_overdue,
                        "created_at": created.isoformat(),
                    }
                )

                log.warning(
                    "Evidence request %s is %d days overdue (assignee=%s)",
                    req.id,
                    days_overdue,
                    assignee,
                )

        return sorted(results, key=lambda r: r["days_overdue"], reverse=True)

    # ------------------------------------------------------------------
    # List requests for an engagement
    # ------------------------------------------------------------------

    def list_requests(
        self,
        session: Session,
        engagement_id: str,
        *,
        status: str | None = None,
    ) -> list[EvidenceRequest]:
        """List evidence requests for an engagement.

        Args:
            session: SQLAlchemy session.
            engagement_id: Engagement UUID.
            status: Optional status filter.

        Returns:
            List of EvidenceRequest objects.
        """
        q = session.query(EvidenceRequest).filter(
            EvidenceRequest.engagement_id == engagement_id,
        )
        if status:
            q = q.filter(EvidenceRequest.status == status)
        return q.order_by(EvidenceRequest.created_at.desc()).all()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_request(self, session: Session, request_id: str) -> EvidenceRequest:
        """Resolve an evidence request by ID or prefix."""
        req = session.get(EvidenceRequest, request_id)
        if req:
            return req
        # Try prefix match
        req = (
            session.query(EvidenceRequest).filter(EvidenceRequest.id.startswith(request_id)).first()
        )
        if not req:
            raise ValueError(f"Evidence request not found: {request_id}")
        return req
