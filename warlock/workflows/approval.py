"""GAP-042: Multi-level approval workflow engine.

Stores approval state in the AuditEntry trail via AuditTrail.record().
Approval requests are tracked as JSON metadata on audit entries with
action prefix ``approval_*``.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import AuditEntry, _uuid

log = logging.getLogger(__name__)


class ApprovalChain:
    """Multi-level approval workflow backed by the audit trail."""

    def __init__(self, session: Session):
        self.session = session

    def create_request(
        self,
        entity_type: str,
        entity_id: str,
        requester: str,
        approvers: list[str],
        metadata: dict | None = None,
    ) -> str:
        """Create an approval request with an ordered approver chain.

        Args:
            entity_type: Type of entity needing approval (e.g. "poam", "policy").
            entity_id: ID of the entity.
            requester: Who is requesting approval.
            approvers: Ordered list of approver identifiers.
            metadata: Optional extra context.

        Returns:
            The request_id (audit entry entity_id) for tracking.
        """
        request_id = _uuid()
        audit = AuditTrail(self.session)
        audit.record(
            action="approval_requested",
            entity_type=entity_type,
            entity_id=request_id,
            actor=requester,
            metadata={
                "target_entity_id": entity_id,
                "requester": requester,
                "approvers": approvers,
                "current_level": 0,
                "status": "pending",
                **(metadata or {}),
            },
        )
        log.info(
            "Approval request %s created for %s/%s by %s (approvers: %s)",
            request_id,
            entity_type,
            entity_id,
            requester,
            approvers,
        )
        return request_id

    def approve(
        self,
        request_id: str,
        approver: str,
        notes: str | None = None,
    ) -> dict:
        """Record approval from the current-level approver.

        Auto-advances to the next level. If all levels are approved,
        marks the request as ``approved``.

        Args:
            request_id: The approval request ID.
            approver: Who is approving.
            notes: Optional approval notes.

        Returns:
            Dict with ``status`` ("approved" or "pending_next_level")
            and ``level``.

        Raises:
            ValueError: If request not found, already resolved, or
                wrong approver for current level.
        """
        request = self._get_latest_request(request_id)
        meta = request.metadata_ or {}

        if meta.get("status") in ("approved", "rejected"):
            raise ValueError(f"Request {request_id} already resolved: {meta['status']}")

        approvers = meta.get("approvers", [])
        current_level = meta.get("current_level", 0)

        if current_level >= len(approvers):
            raise ValueError(f"No more approval levels for request {request_id}")

        expected = approvers[current_level]
        if approver != expected:
            raise ValueError(
                f"Approver '{approver}' is not the current-level approver "
                f"(expected '{expected}' at level {current_level})"
            )

        next_level = current_level + 1
        is_final = next_level >= len(approvers)
        status = "approved" if is_final else "pending_next_level"

        audit = AuditTrail(self.session)
        audit.record(
            action="approval_granted",
            entity_type=request.entity_type,
            entity_id=request_id,
            actor=approver,
            metadata={
                "target_entity_id": meta.get("target_entity_id"),
                "level": current_level,
                "approver": approver,
                "notes": notes or "",
                "approvers": approvers,
                "current_level": next_level,
                "status": status,
            },
        )

        log.info(
            "Approval granted on %s by %s (level %d) -> %s",
            request_id,
            approver,
            current_level,
            status,
        )
        return {"status": status, "level": current_level}

    def reject(
        self,
        request_id: str,
        approver: str,
        reason: str,
    ) -> dict:
        """Reject the approval request.

        Args:
            request_id: The approval request ID.
            approver: Who is rejecting.
            reason: Rejection reason.

        Returns:
            Dict with ``status`` = "rejected".

        Raises:
            ValueError: If request not found or already resolved.
        """
        request = self._get_latest_request(request_id)
        meta = request.metadata_ or {}

        if meta.get("status") in ("approved", "rejected"):
            raise ValueError(f"Request {request_id} already resolved: {meta['status']}")

        audit = AuditTrail(self.session)
        audit.record(
            action="approval_rejected",
            entity_type=request.entity_type,
            entity_id=request_id,
            actor=approver,
            metadata={
                "target_entity_id": meta.get("target_entity_id"),
                "requester": meta.get("requester"),
                "approver": approver,
                "reason": reason,
                "status": "rejected",
            },
        )

        log.info(
            "Approval rejected on %s by %s: %s",
            request_id,
            approver,
            reason,
        )
        return {"status": "rejected"}

    def get_pending(self, approver: str) -> list[dict]:
        """Get all requests pending this approver's decision.

        Scans approval_requested and approval_granted entries to find
        requests where ``approver`` is the current-level approver and
        the request is not yet resolved.

        Args:
            approver: The approver to look up.

        Returns:
            List of dicts with request info.
        """
        # Find the latest audit entry for each approval request.
        # We look for entries where the approver is expected at the
        # current level and the request is still pending.
        pending: list[dict] = []

        # Get all approval-related entries, most recent first
        entries = (
            self.session.query(AuditEntry)
            .filter(
                AuditEntry.action.in_(
                    [
                        "approval_requested",
                        "approval_granted",
                        "approval_rejected",
                    ]
                )
            )
            .order_by(AuditEntry.sequence.desc())
            .all()
        )

        # Track the latest state per request_id
        seen: set[str] = set()
        for entry in entries:
            rid = entry.entity_id
            if rid in seen:
                continue
            seen.add(rid)

            meta = entry.metadata_ or {}
            status = meta.get("status", "")
            if status in ("approved", "rejected"):
                continue

            approvers = meta.get("approvers", [])
            current_level = meta.get("current_level", 0)
            if current_level < len(approvers) and approvers[current_level] == approver:
                pending.append(
                    {
                        "request_id": rid,
                        "entity_type": entry.entity_type,
                        "target_entity_id": meta.get("target_entity_id"),
                        "requester": meta.get("requester"),
                        "current_level": current_level,
                        "approvers": approvers,
                    }
                )

        return pending

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_latest_request(self, request_id: str) -> AuditEntry:
        """Find the most recent audit entry for an approval request.

        Raises:
            ValueError: If no entries found for this request_id.
        """
        entry = (
            self.session.query(AuditEntry)
            .filter(
                AuditEntry.entity_id == request_id,
                AuditEntry.action.in_(
                    [
                        "approval_requested",
                        "approval_granted",
                        "approval_rejected",
                    ]
                ),
            )
            .order_by(AuditEntry.sequence.desc())
            .first()
        )
        if not entry:
            raise ValueError(f"Approval request not found: {request_id}")
        return entry
