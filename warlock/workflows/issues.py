"""Issue tracking and remediation lifecycle management."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlResult,
    Finding,
    Issue,
    IssueComment,
)


class IssueManager:
    """Manages the lifecycle of compliance issues."""

    VALID_STATUSES = {
        "open", "assigned", "in_progress", "remediated",
        "verified", "closed", "risk_accepted",
    }
    VALID_TRANSITIONS = {
        "open": {"assigned", "risk_accepted", "closed"},
        "assigned": {"in_progress", "open", "risk_accepted"},
        "in_progress": {"remediated", "assigned", "risk_accepted"},
        "remediated": {"verified", "in_progress"},
        "verified": {"closed", "remediated"},
        "closed": {"open"},  # reopen
        "risk_accepted": {"open"},  # revoke acceptance
    }

    PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _severity_to_priority(self, severity: str) -> str:
        """Map finding/result severity to issue priority."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "low",
        }
        return mapping.get(severity, "medium")

    def create_from_finding(
        self,
        session: Session,
        finding_id: str,
        control_result_id: str,
        created_by: str = "pipeline",
    ) -> Issue:
        """Create an issue from a specific finding and control result."""
        finding = session.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        result = session.query(ControlResult).filter(ControlResult.id == control_result_id).first()
        if not result:
            raise ValueError(f"ControlResult not found: {control_result_id}")

        issue = Issue(
            title=f"[{result.framework}/{result.control_id}] {finding.title}",
            description=result.remediation_summary or finding.title,
            finding_id=finding_id,
            control_result_id=control_result_id,
            framework=result.framework,
            control_id=result.control_id,
            status="open",
            priority=self._severity_to_priority(result.severity),
            source="pipeline",
            created_by=created_by,
            remediation_plan="\n".join(result.remediation_steps) if result.remediation_steps else None,
        )
        session.add(issue)
        session.flush()

        self.add_comment(
            session, issue.id, created_by,
            f"Issue auto-created from finding {finding_id[:8]}... (control result {control_result_id[:8]}...)",
            comment_type="status_change",
        )

        return issue

    def create_from_poam(
        self,
        session: Session,
        framework: str,
        control_id: str,
        title: str,
        description: str,
        priority: str,
        created_by: str,
    ) -> Issue:
        """Create an issue manually (e.g. from a POA&M import)."""
        if priority not in self.PRIORITY_ORDER:
            raise ValueError(f"Invalid priority: {priority}. Must be one of {set(self.PRIORITY_ORDER)}")

        issue = Issue(
            title=title,
            description=description,
            framework=framework,
            control_id=control_id,
            status="open",
            priority=priority,
            source="manual",
            created_by=created_by,
        )
        session.add(issue)
        session.flush()
        return issue

    def transition(
        self,
        session: Session,
        issue_id: str,
        new_status: str,
        actor: str,
        notes: str | None = None,
    ) -> Issue:
        """Transition an issue to a new status with validation."""
        issue = session.query(Issue).filter(Issue.id == issue_id).first()
        if not issue:
            raise ValueError(f"Issue not found: {issue_id}")

        if new_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status}. Must be one of {self.VALID_STATUSES}")

        allowed = self.VALID_TRANSITIONS.get(issue.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Cannot transition from '{issue.status}' to '{new_status}'. "
                f"Allowed transitions: {allowed}"
            )

        old_status = issue.status
        now = datetime.now(timezone.utc)
        issue.status = new_status
        issue.updated_at = now

        # Set lifecycle timestamps
        if new_status == "remediated":
            issue.remediated_at = now
        elif new_status == "verified":
            issue.verified_at = now
        elif new_status == "closed":
            issue.closed_at = now
        elif new_status == "open" and old_status == "closed":
            # Reopening — clear closed timestamp
            issue.closed_at = None

        self.add_comment(
            session, issue_id, actor,
            f"Status changed from '{old_status}' to '{new_status}'"
            + (f": {notes}" if notes else ""),
            comment_type="status_change",
        )

        return issue

    def assign(
        self,
        session: Session,
        issue_id: str,
        assigned_to: str,
        assigned_by: str,
    ) -> Issue:
        """Assign an issue to a user and transition to 'assigned' if currently 'open'."""
        issue = session.query(Issue).filter(Issue.id == issue_id).first()
        if not issue:
            raise ValueError(f"Issue not found: {issue_id}")

        now = datetime.now(timezone.utc)
        issue.assigned_to = assigned_to
        issue.assigned_by = assigned_by
        issue.assigned_at = now
        issue.updated_at = now

        # Auto-transition from open to assigned
        if issue.status == "open":
            issue.status = "assigned"

        self.add_comment(
            session, issue_id, assigned_by,
            f"Assigned to {assigned_to}",
            comment_type="assignment",
        )

        return issue

    def accept_risk(
        self,
        session: Session,
        issue_id: str,
        owner: str,
        justification: str,
        expiry_days: int = 90,
        actor: str = "",
    ) -> Issue:
        """Accept risk for an issue instead of remediating."""
        issue = session.query(Issue).filter(Issue.id == issue_id).first()
        if not issue:
            raise ValueError(f"Issue not found: {issue_id}")

        if not justification:
            raise ValueError("Risk acceptance requires a justification")

        allowed = self.VALID_TRANSITIONS.get(issue.status, set())
        if "risk_accepted" not in allowed:
            raise ValueError(
                f"Cannot accept risk from status '{issue.status}'. "
                f"Allowed transitions: {allowed}"
            )

        now = datetime.now(timezone.utc)
        issue.status = "risk_accepted"
        issue.risk_accepted = True
        issue.risk_acceptance_owner = owner
        issue.risk_acceptance_justification = justification
        issue.risk_acceptance_expiry = now + timedelta(days=expiry_days)
        issue.updated_at = now

        self.add_comment(
            session, issue_id, actor or owner,
            f"Risk accepted by {owner}. Justification: {justification}. "
            f"Expires in {expiry_days} days.",
            comment_type="status_change",
        )

        return issue

    def add_evidence(
        self,
        session: Session,
        issue_id: str,
        description: str,
        url: str,
        actor: str,
    ) -> Issue:
        """Add remediation evidence to an issue."""
        issue = session.query(Issue).filter(Issue.id == issue_id).first()
        if not issue:
            raise ValueError(f"Issue not found: {issue_id}")

        now = datetime.now(timezone.utc)
        evidence_list = list(issue.remediation_evidence or [])
        evidence_list.append({
            "description": description,
            "url": url,
            "uploaded_at": now.isoformat(),
        })
        issue.remediation_evidence = evidence_list
        issue.updated_at = now

        self.add_comment(
            session, issue_id, actor,
            f"Evidence added: {description} ({url})",
            comment_type="evidence",
        )

        return issue

    def add_comment(
        self,
        session: Session,
        issue_id: str,
        author: str,
        content: str,
        comment_type: str = "comment",
    ) -> IssueComment:
        """Add a comment to an issue."""
        comment = IssueComment(
            issue_id=issue_id,
            author=author,
            content=content,
            comment_type=comment_type,
        )
        session.add(comment)
        session.flush()
        return comment

    def auto_create_from_results(
        self,
        session: Session,
        framework: str | None = None,
    ) -> list[Issue]:
        """Scan ControlResults for non-compliant items and auto-create issues
        for any that don't already have one."""
        query = session.query(ControlResult).filter(
            ControlResult.status == "non_compliant"
        )
        if framework:
            query = query.filter(ControlResult.framework == framework)

        results = query.all()
        created: list[Issue] = []

        for result in results:
            # Check if an issue already exists for this control result
            existing = session.query(Issue).filter(
                Issue.control_result_id == result.id,
            ).first()
            if existing:
                continue

            try:
                issue = self.create_from_finding(
                    session,
                    finding_id=result.finding_id,
                    control_result_id=result.id,
                    created_by="pipeline",
                )
                created.append(issue)
            except ValueError:
                # Finding may not exist; skip
                continue

        return created

    def summary(
        self,
        session: Session,
        framework: str | None = None,
    ) -> dict[str, Any]:
        """Return issue counts by status and priority."""
        query = session.query(
            Issue.status,
            Issue.priority,
            func.count(Issue.id),
        ).group_by(Issue.status, Issue.priority)

        if framework:
            query = query.filter(Issue.framework == framework)

        rows = query.all()

        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        total = 0

        for status_val, priority_val, cnt in rows:
            by_status[status_val] = by_status.get(status_val, 0) + cnt
            by_priority[priority_val] = by_priority.get(priority_val, 0) + cnt
            total += cnt

        # Overdue count
        now = datetime.now(timezone.utc)
        overdue = session.query(func.count(Issue.id)).filter(
            Issue.due_date < now,
            Issue.status.notin_(["closed", "risk_accepted", "verified"]),
        )
        if framework:
            overdue = overdue.filter(Issue.framework == framework)
        overdue_count = overdue.scalar() or 0

        return {
            "total": total,
            "by_status": by_status,
            "by_priority": by_priority,
            "overdue": overdue_count,
        }
