"""Attestation and audit collaboration workflow."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import (
    Attestation,
    AuditComment,
    AuditEngagement,
    ControlResult,
)


class AttestationManager:
    """Manages the sign-off workflow for control assessments.

    Enforces separation of duties: the preparer, reviewer, and approver
    must all be different actors.
    """

    VALID_STATUSES = {"draft", "submitted", "reviewed", "approved", "rejected"}
    VALID_TRANSITIONS = {
        "draft": {"submitted"},
        "submitted": {"reviewed", "rejected"},
        "reviewed": {"approved", "rejected"},
        "approved": set(),  # final
        "rejected": {"draft"},  # back to drafting
    }

    def create(
        self,
        session: Session,
        framework: str,
        statement: str,
        prepared_by: str,
        control_id: str | None = None,
        engagement_id: str | None = None,
    ) -> Attestation:
        """Create a new attestation in draft status."""
        if engagement_id:
            eng = session.query(AuditEngagement).filter(
                AuditEngagement.id == engagement_id
            ).first()
            if not eng:
                raise ValueError(f"Engagement not found: {engagement_id}")

        now = datetime.now(timezone.utc)
        attestation = Attestation(
            engagement_id=engagement_id,
            framework=framework,
            control_id=control_id,
            status="draft",
            statement=statement,
            prepared_by=prepared_by,
            prepared_at=now,
        )
        session.add(attestation)
        session.flush()
        return attestation

    def submit(
        self,
        session: Session,
        attestation_id: str,
        submitted_by: str,
    ) -> Attestation:
        """Submit for review. Enforces: submitted_by != reviewed_by (checked at review time)."""
        att = session.query(Attestation).filter(Attestation.id == attestation_id).first()
        if not att:
            raise ValueError(f"Attestation not found: {attestation_id}")

        self._validate_transition(att.status, "submitted")

        now = datetime.now(timezone.utc)
        att.status = "submitted"
        att.submitted_by = submitted_by
        att.submitted_at = now
        att.updated_at = now
        session.flush()
        return att

    def review(
        self,
        session: Session,
        attestation_id: str,
        reviewed_by: str,
        notes: str | None = None,
    ) -> Attestation:
        """Mark as reviewed. Enforces: reviewed_by != prepared_by."""
        att = session.query(Attestation).filter(Attestation.id == attestation_id).first()
        if not att:
            raise ValueError(f"Attestation not found: {attestation_id}")

        self._validate_transition(att.status, "reviewed")

        # Separation of duties: reviewer must not be the preparer
        if reviewed_by == att.prepared_by:
            raise ValueError(
                "Separation of duties violation: reviewer cannot be the same person "
                f"as the preparer ({att.prepared_by})"
            )

        now = datetime.now(timezone.utc)
        att.status = "reviewed"
        att.reviewed_by = reviewed_by
        att.reviewed_at = now
        att.review_notes = notes
        att.updated_at = now
        session.flush()
        return att

    def approve(
        self,
        session: Session,
        attestation_id: str,
        approved_by: str,
    ) -> Attestation:
        """Approve. Enforces: approved_by != prepared_by and approved_by != submitted_by."""
        att = session.query(Attestation).filter(Attestation.id == attestation_id).first()
        if not att:
            raise ValueError(f"Attestation not found: {attestation_id}")

        self._validate_transition(att.status, "approved")

        # Separation of duties: approver must differ from preparer and submitter
        if approved_by == att.prepared_by:
            raise ValueError(
                "Separation of duties violation: approver cannot be the same person "
                f"as the preparer ({att.prepared_by})"
            )
        if approved_by == att.submitted_by:
            raise ValueError(
                "Separation of duties violation: approver cannot be the same person "
                f"as the submitter ({att.submitted_by})"
            )

        now = datetime.now(timezone.utc)
        att.status = "approved"
        att.approved_by = approved_by
        att.approved_at = now
        att.updated_at = now
        session.flush()
        return att

    def reject(
        self,
        session: Session,
        attestation_id: str,
        rejected_by: str,
        reason: str,
    ) -> Attestation:
        """Reject an attestation back to draft."""
        att = session.query(Attestation).filter(Attestation.id == attestation_id).first()
        if not att:
            raise ValueError(f"Attestation not found: {attestation_id}")

        # Can reject from submitted or reviewed
        allowed = self.VALID_TRANSITIONS.get(att.status, set())
        if "rejected" not in allowed and "draft" not in allowed:
            raise ValueError(
                f"Cannot reject from status '{att.status}'. "
                f"Allowed transitions: {allowed}"
            )

        now = datetime.now(timezone.utc)
        att.status = "rejected"
        att.rejected_by = rejected_by
        att.rejected_at = now
        att.rejection_reason = reason
        att.updated_at = now
        session.flush()
        return att

    def list_for_engagement(
        self,
        session: Session,
        engagement_id: str,
    ) -> list[Attestation]:
        """List all attestations for an engagement."""
        return (
            session.query(Attestation)
            .filter(Attestation.engagement_id == engagement_id)
            .order_by(Attestation.created_at.desc())
            .all()
        )

    def generate_management_assertion(
        self,
        session: Session,
        engagement_id: str,
        framework: str,
    ) -> Attestation:
        """Auto-generate a management assertion from posture data."""
        eng = session.query(AuditEngagement).filter(
            AuditEngagement.id == engagement_id
        ).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        # Get latest posture data for the framework
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.assessed_at >= eng.period_start,
                ControlResult.assessed_at <= eng.period_end,
            )
            .all()
        )

        total = len(results)
        compliant = sum(1 for r in results if r.status == "compliant")
        non_compliant = sum(1 for r in results if r.status == "non_compliant")
        rate = round(compliant / total * 100, 1) if total > 0 else 0.0

        period_start_str = eng.period_start.strftime("%Y-%m-%d") if eng.period_start else "N/A"
        period_end_str = eng.period_end.strftime("%Y-%m-%d") if eng.period_end else "N/A"

        statement = (
            f"Management asserts that for the period {period_start_str} "
            f"to {period_end_str}, the {framework} controls have been assessed. "
            f"Of {total} control assessments, {compliant} ({rate}%) were found compliant "
            f"and {non_compliant} were found non-compliant. "
            f"Management is responsible for the design, implementation, and maintenance "
            f"of effective internal controls relevant to the {framework} framework."
        )

        # Build evidence references from non-compliant results
        evidence_refs = [
            {"finding_id": r.finding_id, "description": f"{r.control_id}: {r.status}"}
            for r in results
            if r.status == "non_compliant"
        ][:50]  # cap at 50 references

        attestation = Attestation(
            engagement_id=engagement_id,
            framework=framework,
            status="draft",
            statement=statement,
            evidence_references=evidence_refs,
            prepared_by="system",
            prepared_at=datetime.now(timezone.utc),
        )
        session.add(attestation)
        session.flush()
        return attestation

    def _validate_transition(self, current: str, target: str) -> None:
        """Validate that a status transition is allowed."""
        if target not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {target}. Must be one of {self.VALID_STATUSES}")
        allowed = self.VALID_TRANSITIONS.get(current, set())
        if target not in allowed:
            raise ValueError(
                f"Cannot transition from '{current}' to '{target}'. "
                f"Allowed transitions: {allowed}"
            )


class AuditCollaboration:
    """Manages auditor-practitioner collaboration comments."""

    VALID_TARGET_TYPES = {"control", "finding", "attestation", "engagement"}
    VALID_ROLES = {"auditor", "practitioner", "management"}

    def add_comment(
        self,
        session: Session,
        engagement_id: str,
        target_type: str,
        target_id: str,
        author: str,
        author_role: str,
        content: str,
        parent_id: str | None = None,
    ) -> AuditComment:
        """Add a comment to a target within an engagement."""
        if target_type not in self.VALID_TARGET_TYPES:
            raise ValueError(
                f"Invalid target_type: {target_type}. "
                f"Must be one of {self.VALID_TARGET_TYPES}"
            )
        if author_role and author_role not in self.VALID_ROLES:
            raise ValueError(
                f"Invalid author_role: {author_role}. "
                f"Must be one of {self.VALID_ROLES}"
            )

        # Validate engagement exists
        eng = session.query(AuditEngagement).filter(
            AuditEngagement.id == engagement_id
        ).first()
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        # Validate parent exists if threading
        if parent_id:
            parent = session.query(AuditComment).filter(
                AuditComment.id == parent_id
            ).first()
            if not parent:
                raise ValueError(f"Parent comment not found: {parent_id}")
            if parent.engagement_id != engagement_id:
                raise ValueError("Parent comment belongs to a different engagement")

        comment = AuditComment(
            engagement_id=engagement_id,
            target_type=target_type,
            target_id=target_id,
            author=author,
            author_role=author_role,
            content=content,
            parent_id=parent_id,
        )
        session.add(comment)
        session.flush()
        return comment

    def resolve_comment(
        self,
        session: Session,
        comment_id: str,
        resolved_by: str,
    ) -> AuditComment:
        """Resolve a comment thread."""
        comment = session.query(AuditComment).filter(
            AuditComment.id == comment_id
        ).first()
        if not comment:
            raise ValueError(f"Comment not found: {comment_id}")

        now = datetime.now(timezone.utc)
        comment.resolved = True
        comment.resolved_by = resolved_by
        comment.resolved_at = now
        session.flush()
        return comment

    def get_thread(
        self,
        session: Session,
        comment_id: str,
    ) -> list[AuditComment]:
        """Get a comment and all its replies."""
        root = session.query(AuditComment).filter(
            AuditComment.id == comment_id
        ).first()
        if not root:
            raise ValueError(f"Comment not found: {comment_id}")

        replies = (
            session.query(AuditComment)
            .filter(AuditComment.parent_id == comment_id)
            .order_by(AuditComment.created_at.asc())
            .all()
        )

        return [root] + replies

    def comments_for_control(
        self,
        session: Session,
        engagement_id: str,
        control_id: str,
    ) -> list[AuditComment]:
        """Get all comments for a specific control within an engagement."""
        return (
            session.query(AuditComment)
            .filter(
                AuditComment.engagement_id == engagement_id,
                AuditComment.target_type == "control",
                AuditComment.target_id == control_id,
            )
            .order_by(AuditComment.created_at.asc())
            .all()
        )

    def comments_for_engagement(
        self,
        session: Session,
        engagement_id: str,
    ) -> list[AuditComment]:
        """Get all comments for an engagement."""
        return (
            session.query(AuditComment)
            .filter(AuditComment.engagement_id == engagement_id)
            .order_by(AuditComment.created_at.asc())
            .all()
        )

    def unresolved_count(
        self,
        session: Session,
        engagement_id: str,
    ) -> int:
        """Count unresolved top-level comments for an engagement."""
        return (
            session.query(func.count(AuditComment.id))
            .filter(
                AuditComment.engagement_id == engagement_id,
                AuditComment.resolved == False,  # noqa: E712
                AuditComment.parent_id == None,  # noqa: E711 — top-level only
            )
            .scalar() or 0
        )
