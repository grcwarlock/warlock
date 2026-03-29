"""Access Review Campaign Management.

Creates and manages periodic access review campaigns:
  - Scope by org unit, system, or role
  - Generate review items from IAM/personnel data
  - Assign reviewers (managers) with deadlines
  - Track decisions: approve / revoke / escalate
  - Campaign completion tracking and certification
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import Finding, Personnel
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Campaign statuses and transitions
_CAMPAIGN_STATUSES = ("draft", "active", "in_review", "completed", "certified")
_CAMPAIGN_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"active"},
    "active": {"in_review"},
    "in_review": {"completed"},
    "completed": {"certified"},
    "certified": set(),
}

# Review item decisions
_VALID_DECISIONS = ("approve", "revoke", "escalate")


class AccessReviewCampaignManager:
    """Manages access review campaigns end-to-end."""

    # ------------------------------------------------------------------
    # Create campaign
    # ------------------------------------------------------------------

    def create_campaign(
        self,
        session: Session,
        name: str,
        scope: dict,
        *,
        due_date: datetime | None = None,
        actor: str = "system",
    ) -> dict:
        """Create an access review campaign.

        Args:
            session: SQLAlchemy session.
            name: Campaign name (e.g. "Q1 2026 Privileged Access Review").
            scope: Dict with optional keys: department, system_id, role,
                   resource_type, include_terminated (bool).
            due_date: Campaign deadline (defaults to 14 days from now).
            actor: Who created the campaign.

        Returns:
            Dict with campaign_id, name, scope, due_date, status, item_count.
        """
        campaign_id = str(uuid4())
        now = datetime.now(timezone.utc)
        due = due_date or (now + timedelta(days=14))

        # Generate review items based on scope
        items = self._generate_review_items(session, scope)

        campaign = {
            "id": campaign_id,
            "name": name,
            "scope": scope,
            "status": "draft",
            "created_at": now.isoformat(),
            "due_date": due.isoformat(),
            "created_by": actor,
            "items": items,
            "item_count": len(items),
            "decisions": {"approve": 0, "revoke": 0, "escalate": 0, "pending": len(items)},
        }

        audit = AuditTrail(session)
        audit.record(
            action="access_review_campaign_created",
            entity_type="access_review_campaign",
            entity_id=campaign_id,
            actor=actor,
            metadata={
                "name": name,
                "scope": scope,
                "item_count": len(items),
                "due_date": due.isoformat(),
            },
        )

        log.info(
            "Access review campaign '%s' created: %d items, due %s",
            name,
            len(items),
            due.isoformat(),
        )
        return campaign

    # ------------------------------------------------------------------
    # Generate review items from IAM data
    # ------------------------------------------------------------------

    def _generate_review_items(
        self,
        session: Session,
        scope: dict,
    ) -> list[dict]:
        """Generate review items from personnel and IAM finding data.

        Args:
            session: SQLAlchemy session.
            scope: Scoping criteria.

        Returns:
            List of review item dicts.
        """
        items = []

        # Query personnel matching scope
        q = session.query(Personnel).filter(Personnel.is_active.is_(True))

        dept = scope.get("department")
        if dept:
            q = q.filter(Personnel.department == dept)

        role = scope.get("role")
        if role:
            q = q.filter(Personnel.title.ilike(f"%{role}%"))

        include_terminated = scope.get("include_terminated", False)
        if include_terminated:
            q = session.query(Personnel)  # include all
            if dept:
                q = q.filter(Personnel.department == dept)

        personnel = q.all()

        for person in personnel:
            # Build review item from personnel data
            item = {
                "id": str(uuid4()),
                "personnel_id": person.id,
                "email": person.email,
                "full_name": person.full_name,
                "department": person.department or "N/A",
                "title": person.title or "N/A",
                "manager_email": person.manager_email or "N/A",
                "reviewer": person.manager_email or "unassigned",
                "idp_status": person.idp_status or "unknown",
                "hr_status": person.hr_status or "unknown",
                "mfa_enabled": person.mfa_enabled,
                "last_login": (
                    ensure_aware(person.idp_last_login).isoformat()
                    if person.idp_last_login
                    else "N/A"
                ),
                "groups": list(person.idp_groups or []),
                "flags": list(person.flags or []),
                "risk_score": person.risk_score or 0.0,
                "decision": "pending",
                "decision_by": None,
                "decision_at": None,
                "notes": None,
            }
            items.append(item)

        # Also check IAM findings for the scope
        resource_type = scope.get("resource_type")
        if resource_type:
            iam_findings = (
                session.query(Finding)
                .filter(
                    Finding.resource_type == resource_type,
                    Finding.observation_type.in_(
                        ["access_anomaly", "policy_violation", "misconfiguration"]
                    ),
                )
                .limit(100)
                .all()
            )

            seen_resources = {i["email"] for i in items}
            for f in iam_findings:
                if f.resource_id and f.resource_id not in seen_resources:
                    seen_resources.add(f.resource_id)
                    detail = f.detail or {}
                    items.append(
                        {
                            "id": str(uuid4()),
                            "personnel_id": None,
                            "email": detail.get("email", f.resource_id),
                            "full_name": detail.get("name", f.resource_name or f.resource_id),
                            "department": detail.get("department", "N/A"),
                            "title": detail.get("title", "N/A"),
                            "manager_email": detail.get("manager_email", "N/A"),
                            "reviewer": detail.get("manager_email", "unassigned"),
                            "idp_status": detail.get("status", "unknown"),
                            "hr_status": "unknown",
                            "mfa_enabled": detail.get("mfa_enabled"),
                            "last_login": "N/A",
                            "groups": detail.get("groups", []),
                            "flags": [],
                            "risk_score": 0.0,
                            "decision": "pending",
                            "decision_by": None,
                            "decision_at": None,
                            "notes": None,
                        }
                    )

        return items

    # ------------------------------------------------------------------
    # Record decision
    # ------------------------------------------------------------------

    def record_decision(
        self,
        session: Session,
        campaign: dict,
        item_id: str,
        decision: str,
        *,
        decided_by: str = "system",
        notes: str | None = None,
    ) -> dict:
        """Record a review decision for a campaign item.

        Args:
            session: SQLAlchemy session.
            campaign: Campaign dict (as returned by create_campaign).
            item_id: Review item UUID (or prefix).
            decision: "approve", "revoke", or "escalate".
            decided_by: Who made the decision.
            notes: Decision notes.

        Returns:
            Updated campaign dict.

        Raises:
            ValueError: If invalid decision or item not found.
        """
        if decision not in _VALID_DECISIONS:
            raise ValueError(f"Invalid decision '{decision}'. Must be one of: {_VALID_DECISIONS}")

        # Find the item
        item = None
        for i in campaign.get("items", []):
            if i["id"] == item_id or i["id"].startswith(item_id):
                item = i
                break

        if not item:
            raise ValueError(f"Review item not found: {item_id}")

        now = datetime.now(timezone.utc)
        old_decision = item["decision"]
        item["decision"] = decision
        item["decision_by"] = decided_by
        item["decision_at"] = now.isoformat()
        item["notes"] = notes

        # Update decision counts
        decisions = campaign["decisions"]
        if old_decision == "pending":
            decisions["pending"] = max(0, decisions["pending"] - 1)
        elif old_decision in decisions:
            decisions[old_decision] = max(0, decisions[old_decision] - 1)
        decisions[decision] = decisions.get(decision, 0) + 1

        audit = AuditTrail(session)
        audit.record(
            action="access_review_decision",
            entity_type="access_review_campaign",
            entity_id=campaign["id"],
            actor=decided_by,
            metadata={
                "item_id": item_id,
                "email": item.get("email", ""),
                "decision": decision,
                "notes": notes,
            },
        )

        log.info(
            "Access review decision: %s for %s (campaign %s)",
            decision,
            item.get("email", item_id),
            campaign["id"][:8],
        )
        return campaign

    # ------------------------------------------------------------------
    # Campaign completion
    # ------------------------------------------------------------------

    def get_completion_status(self, campaign: dict) -> dict:
        """Get campaign completion statistics.

        Args:
            campaign: Campaign dict.

        Returns:
            Dict with total, reviewed, pending, completion_pct, is_complete.
        """
        total = campaign.get("item_count", 0)
        decisions = campaign.get("decisions", {})
        pending = decisions.get("pending", total)
        reviewed = total - pending

        return {
            "campaign_id": campaign["id"],
            "campaign_name": campaign["name"],
            "total": total,
            "reviewed": reviewed,
            "pending": pending,
            "completion_pct": round((reviewed / total * 100) if total > 0 else 0, 1),
            "is_complete": pending == 0,
            "decisions": decisions,
        }

    def certify_campaign(
        self,
        session: Session,
        campaign: dict,
        *,
        certified_by: str = "system",
    ) -> dict:
        """Certify a completed campaign.

        Args:
            session: SQLAlchemy session.
            campaign: Campaign dict (must be 100% complete).
            certified_by: Who certified the campaign.

        Returns:
            Updated campaign dict with certified status.

        Raises:
            ValueError: If campaign is not complete.
        """
        status = self.get_completion_status(campaign)
        if not status["is_complete"]:
            raise ValueError(
                f"Cannot certify campaign with {status['pending']} pending items. "
                f"All items must be reviewed before certification."
            )

        now = datetime.now(timezone.utc)
        campaign["status"] = "certified"
        campaign["certified_by"] = certified_by
        campaign["certified_at"] = now.isoformat()

        audit = AuditTrail(session)
        audit.record(
            action="access_review_campaign_certified",
            entity_type="access_review_campaign",
            entity_id=campaign["id"],
            actor=certified_by,
            metadata={
                "name": campaign["name"],
                "total_items": status["total"],
                "decisions": status["decisions"],
            },
        )

        log.info(
            "Access review campaign '%s' certified by %s (%d items reviewed)",
            campaign["name"],
            certified_by,
            status["total"],
        )
        return campaign
