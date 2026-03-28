"""GAP-053: Document management / policy repository.

Manages Policy lifecycle with version tracking via PolicyHistory.
The Policy model stores rules as JSON; we use the ``description``
field for policy content text and ``policy_type`` for classification.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import Policy, PolicyHistory
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


class PolicyManager:
    """Manages policy creation, versioning, and review scheduling."""

    def create_policy(
        self,
        session: Session,
        title: str,
        content: str,
        policy_type: str,
        created_by: str,
    ) -> Policy:
        """Create a new policy document.

        Args:
            session: SQLAlchemy session.
            title: Policy title.
            content: Policy body text (stored in description).
            policy_type: Classification (e.g. "security", "privacy", "acceptable_use").
            created_by: Author email/identifier.

        Returns:
            Newly created Policy.
        """
        policy = Policy(
            policy_type=policy_type,
            scope={"title": title},
            rules={"content": content, "version": 1},
            created_by=created_by,
            description=content,
        )
        session.add(policy)
        session.flush()

        # Record initial version in history
        history = PolicyHistory(
            policy_id=str(policy.id),
            action="created",
            old_rules={},
            new_rules=policy.rules,
            actor=created_by,
        )
        session.add(history)
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="policy_created",
            entity_type="policy",
            entity_id=str(policy.id),
            actor=created_by,
            metadata={
                "title": title,
                "policy_type": policy_type,
                "version": 1,
            },
        )

        log.info(
            "Policy %s created: '%s' (type=%s) by %s",
            policy.id,
            title,
            policy_type,
            created_by,
        )
        return policy

    def update_policy(
        self,
        session: Session,
        policy_id: str,
        content: str,
        updated_by: str,
        change_reason: str,
    ) -> Policy:
        """Update a policy document, creating a PolicyHistory entry.

        Args:
            session: SQLAlchemy session.
            policy_id: ID of the policy to update.
            content: New policy body text.
            updated_by: Who is making the change.
            change_reason: Why the policy is being updated.

        Returns:
            Updated Policy.

        Raises:
            ValueError: If policy not found.
        """
        policy = session.get(Policy, policy_id)
        if not policy:
            raise ValueError(f"Policy not found: {policy_id}")

        old_rules = dict(policy.rules or {})
        new_version = old_rules.get("version", 0) + 1

        new_rules = {
            "content": content,
            "version": new_version,
            "change_reason": change_reason,
        }

        # Create history entry before updating
        history = PolicyHistory(
            policy_id=str(policy.id),
            action="updated",
            old_rules=old_rules,
            new_rules=new_rules,
            actor=updated_by,
        )
        session.add(history)

        policy.rules = new_rules
        policy.description = content
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="policy_updated",
            entity_type="policy",
            entity_id=str(policy.id),
            actor=updated_by,
            metadata={
                "title": (policy.scope or {}).get("title", ""),
                "version": new_version,
                "change_reason": change_reason,
            },
        )

        log.info(
            "Policy %s updated to v%d by %s: %s",
            policy_id,
            new_version,
            updated_by,
            change_reason,
        )
        return policy

    def get_policy_with_history(
        self,
        session: Session,
        policy_id: str,
    ) -> dict:
        """Retrieve a policy with its full version history.

        Args:
            session: SQLAlchemy session.
            policy_id: ID of the policy.

        Returns:
            Dict with ``policy`` and ``history`` keys.

        Raises:
            ValueError: If policy not found.
        """
        policy = session.get(Policy, policy_id)
        if not policy:
            raise ValueError(f"Policy not found: {policy_id}")

        history = (
            session.query(PolicyHistory)
            .filter(PolicyHistory.policy_id == policy_id)
            .order_by(PolicyHistory.timestamp.desc())
            .all()
        )

        return {
            "policy": policy,
            "history": [
                {
                    "id": str(h.id),
                    "action": h.action,
                    "actor": h.actor,
                    "timestamp": ensure_aware(h.timestamp).isoformat() if h.timestamp else None,
                    "old_rules": h.old_rules,
                    "new_rules": h.new_rules,
                }
                for h in history
            ],
        }

    def schedule_review(
        self,
        session: Session,
        policy_id: str,
        review_date: datetime,
        reviewer: str,
    ) -> Policy:
        """Schedule a review for a policy.

        Stores review info in the policy's ``scope`` JSON and records
        the schedule in the audit trail.

        Args:
            session: SQLAlchemy session.
            policy_id: ID of the policy.
            review_date: When the review is due.
            reviewer: Who should review.

        Returns:
            Updated Policy.

        Raises:
            ValueError: If policy not found.
        """
        policy = session.get(Policy, policy_id)
        if not policy:
            raise ValueError(f"Policy not found: {policy_id}")

        scope = dict(policy.scope or {})
        scope["review_date"] = review_date.isoformat()
        scope["reviewer"] = reviewer
        scope["review_status"] = "scheduled"
        policy.scope = scope
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="policy_review_scheduled",
            entity_type="policy",
            entity_id=str(policy.id),
            actor=reviewer,
            metadata={
                "title": scope.get("title", ""),
                "review_date": review_date.isoformat(),
                "reviewer": reviewer,
            },
        )

        log.info(
            "Policy %s review scheduled for %s (reviewer: %s)",
            policy_id,
            review_date.isoformat(),
            reviewer,
        )
        return policy

    def list_due_reviews(self, session: Session) -> list[Policy]:
        """List policies with reviews due on or before today.

        Returns:
            List of Policy rows whose scheduled review_date has passed.
        """
        now = datetime.now(timezone.utc)
        policies = session.query(Policy).filter(Policy.enabled.is_(True)).all()

        due: list[Policy] = []
        for policy in policies:
            scope = policy.scope or {}
            review_date_str = scope.get("review_date")
            if not review_date_str:
                continue
            review_status = scope.get("review_status", "")
            if review_status == "completed":
                continue
            try:
                review_date = datetime.fromisoformat(review_date_str)
                if ensure_aware(review_date) <= now:
                    due.append(policy)
            except (ValueError, TypeError):
                continue

        return due
