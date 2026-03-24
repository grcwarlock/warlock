"""Issue tracking and remediation lifecycle management."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import (
    ControlResult,
    Finding,
    Issue,
    IssueComment,
    WatchSubscription,
)
from warlock.utils import ensure_aware


class IssueManager:
    """Manages the lifecycle of compliance issues."""

    VALID_STATUSES = {
        "open",
        "assigned",
        "in_progress",
        "remediated",
        "verified",
        "closed",
        "risk_accepted",
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
        *,
        skip_audit: bool = False,
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
            remediation_plan="\n".join(result.remediation_steps)
            if result.remediation_steps
            else None,
        )
        session.add(issue)
        session.flush()

        if not skip_audit:
            audit = AuditTrail(session)
            audit.record(
                action="issue_created",
                entity_type="issue",
                entity_id=str(issue.id),
                actor=created_by,
                metadata={
                    "framework": result.framework,
                    "control_id": result.control_id,
                    "source": "pipeline",
                    "finding_id": finding_id,
                },
            )

        self.add_comment(
            session,
            issue.id,
            created_by,
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
            raise ValueError(
                f"Invalid priority: {priority}. Must be one of {set(self.PRIORITY_ORDER)}"
            )

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

        audit = AuditTrail(session)
        audit.record(
            action="issue_created",
            entity_type="issue",
            entity_id=str(issue.id),
            actor=created_by,
            metadata={
                "framework": framework,
                "control_id": control_id,
                "source": "manual",
            },
        )

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

        audit = AuditTrail(session)
        audit.record(
            action=f"issue_transition_{new_status}",
            entity_type="issue",
            entity_id=str(issue.id),
            actor=actor,
            metadata={
                "old_status": old_status,
                "new_status": new_status,
            },
        )

        self.add_comment(
            session,
            issue_id,
            actor,
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
            session,
            issue_id,
            assigned_by,
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
                f"Cannot accept risk from status '{issue.status}'. Allowed transitions: {allowed}"
            )

        now = datetime.now(timezone.utc)
        issue.status = "risk_accepted"
        issue.risk_accepted = True
        issue.risk_acceptance_owner = owner
        issue.risk_acceptance_justification = justification
        issue.risk_acceptance_expiry = now + timedelta(days=expiry_days)
        issue.updated_at = now

        self.add_comment(
            session,
            issue_id,
            actor or owner,
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
        evidence_list.append(
            {
                "description": description,
                "url": url,
                "uploaded_at": now.isoformat(),
            }
        )
        issue.remediation_evidence = evidence_list
        issue.updated_at = now

        self.add_comment(
            session,
            issue_id,
            actor,
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
        query = session.query(ControlResult).filter(ControlResult.status == "non_compliant")
        if framework:
            query = query.filter(ControlResult.framework == framework)

        results = query.all()
        created: list[Issue] = []

        for result in results:
            # W-7: Check for any open issue on the same (framework, control_id)
            existing = (
                session.query(Issue)
                .filter(
                    Issue.framework == result.framework,
                    Issue.control_id == result.control_id,
                    Issue.status.notin_(["closed", "verified", "risk_accepted"]),
                )
                .first()
            )
            if existing:
                continue

            try:
                issue = self.create_from_finding(
                    session,
                    finding_id=result.finding_id,
                    control_result_id=result.id,
                    created_by="pipeline",
                    skip_audit=True,  # Batch: record one summary entry below
                )
                created.append(issue)
            except ValueError:
                # Finding may not exist; skip
                continue

        # Record a single batch audit entry instead of per-issue entries
        if created:
            audit = AuditTrail(session)
            audit.record(
                action="issues_auto_created",
                entity_type="issue",
                entity_id="batch",
                actor="pipeline",
                metadata={"count": len(created), "framework": framework or "all"},
            )

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

    # ------------------------------------------------------------------
    # ISS-4: Watch list
    # ------------------------------------------------------------------

    def watch(
        self,
        session: Session,
        issue_id: str,
        user_id: str,
        actor: str = "",
    ) -> WatchSubscription:
        """Subscribe a user to status changes on an issue.

        Args:
            session: SQLAlchemy session.
            issue_id: ID of the issue to watch.
            user_id: ID of the user subscribing.
            actor: Who initiated the watch (may differ from user_id).

        Returns:
            The created WatchSubscription.

        Raises:
            ValueError: If issue not found or already watching.
        """
        issue = session.query(Issue).filter(Issue.id == issue_id).first()
        if not issue:
            raise ValueError(f"Issue not found: {issue_id}")

        existing = (
            session.query(WatchSubscription)
            .filter(
                WatchSubscription.issue_id == issue_id,
                WatchSubscription.user_id == user_id,
                WatchSubscription.entity_type == "issue",
            )
            .first()
        )
        if existing:
            raise ValueError(f"User {user_id} is already watching issue {issue_id}")

        sub = WatchSubscription(
            user_id=user_id,
            entity_type="issue",
            entity_id=issue_id,
            issue_id=issue_id,
        )
        session.add(sub)
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="issue_watch_added",
            entity_type="issue",
            entity_id=issue_id,
            actor=actor or user_id,
            metadata={"user_id": user_id},
        )

        return sub

    def unwatch(
        self,
        session: Session,
        issue_id: str,
        user_id: str,
        actor: str = "",
    ) -> None:
        """Remove a user's watch subscription from an issue.

        Args:
            session: SQLAlchemy session.
            issue_id: ID of the issue.
            user_id: ID of the user to unsubscribe.
            actor: Who initiated the unwatch.

        Raises:
            ValueError: If issue not found or subscription not found.
        """
        issue = session.query(Issue).filter(Issue.id == issue_id).first()
        if not issue:
            raise ValueError(f"Issue not found: {issue_id}")

        sub = (
            session.query(WatchSubscription)
            .filter(
                WatchSubscription.issue_id == issue_id,
                WatchSubscription.user_id == user_id,
                WatchSubscription.entity_type == "issue",
            )
            .first()
        )
        if not sub:
            raise ValueError(f"User {user_id} is not watching issue {issue_id}")

        session.delete(sub)
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="issue_watch_removed",
            entity_type="issue",
            entity_id=issue_id,
            actor=actor or user_id,
            metadata={"user_id": user_id},
        )

    def get_watchers(
        self,
        session: Session,
        issue_id: str,
    ) -> list[WatchSubscription]:
        """List all watch subscriptions for an issue.

        Args:
            session: SQLAlchemy session.
            issue_id: ID of the issue.

        Returns:
            List of WatchSubscription rows.

        Raises:
            ValueError: If issue not found.
        """
        issue = session.query(Issue).filter(Issue.id == issue_id).first()
        if not issue:
            raise ValueError(f"Issue not found: {issue_id}")

        return (
            session.query(WatchSubscription)
            .filter(
                WatchSubscription.issue_id == issue_id,
                WatchSubscription.entity_type == "issue",
            )
            .order_by(WatchSubscription.created_at)
            .all()
        )

    def get_watched_issues(
        self,
        session: Session,
        user_id: str,
    ) -> list[Issue]:
        """List all issues a user is watching.

        Args:
            session: SQLAlchemy session.
            user_id: ID of the user.

        Returns:
            List of Issue rows the user is subscribed to.
        """
        sub_ids = (
            session.query(WatchSubscription.issue_id)
            .filter(
                WatchSubscription.user_id == user_id,
                WatchSubscription.entity_type == "issue",
                WatchSubscription.issue_id.isnot(None),
            )
            .subquery()
        )
        return (
            session.query(Issue)
            .filter(Issue.id.in_(sub_ids))
            .order_by(Issue.updated_at.desc())
            .all()
        )

    # ------------------------------------------------------------------
    # ISS-3: Velocity tracking
    # ------------------------------------------------------------------

    def velocity_metrics(
        self,
        session: Session,
        framework: str | None = None,
        days: int = 90,
    ) -> dict[str, Any]:
        """Calculate issue velocity metrics over a time window.

        Metrics include mean-time-to-resolve (MTTR) by priority,
        closure rate, and inflow vs outflow counts.

        Args:
            session: SQLAlchemy session.
            framework: Optional framework filter.
            days: Lookback window in days (default 90).

        Returns:
            Dict with mttr_by_priority, closure_rate, inflow, outflow.
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=days)

        # --- Inflow: issues created in the window ---
        inflow_q = session.query(func.count(Issue.id)).filter(
            Issue.created_at >= window_start,
        )
        if framework:
            inflow_q = inflow_q.filter(Issue.framework == framework)
        inflow = inflow_q.scalar() or 0

        # --- Outflow: issues closed in the window ---
        outflow_q = session.query(func.count(Issue.id)).filter(
            Issue.closed_at >= window_start,
            Issue.closed_at.isnot(None),
        )
        if framework:
            outflow_q = outflow_q.filter(Issue.framework == framework)
        outflow = outflow_q.scalar() or 0

        # --- MTTR by priority: average time from created_at to closed_at ---
        closed_q = session.query(Issue).filter(
            Issue.closed_at.isnot(None),
            Issue.closed_at >= window_start,
        )
        if framework:
            closed_q = closed_q.filter(Issue.framework == framework)

        closed_issues = closed_q.all()

        mttr_accum: dict[str, list[float]] = {}
        for issue in closed_issues:
            created = ensure_aware(issue.created_at)
            closed = ensure_aware(issue.closed_at)
            delta_hours = (closed - created).total_seconds() / 3600.0
            priority = issue.priority or "medium"
            mttr_accum.setdefault(priority, []).append(delta_hours)

        mttr_by_priority: dict[str, float] = {}
        for priority, hours_list in mttr_accum.items():
            mttr_by_priority[priority] = round(sum(hours_list) / len(hours_list), 2)

        # --- Closure rate ---
        closure_rate = round(outflow / inflow, 4) if inflow > 0 else 0.0

        return {
            "days": days,
            "inflow": inflow,
            "outflow": outflow,
            "closure_rate": closure_rate,
            "mttr_by_priority_hours": mttr_by_priority,
        }

    # ------------------------------------------------------------------
    # ISS-7: Root cause analysis
    # ------------------------------------------------------------------

    def group_by_root_cause(
        self,
        session: Session,
        framework: str | None = None,
    ) -> list[dict[str, Any]]:
        """Group issues by root_cause_id.

        Args:
            session: SQLAlchemy session.
            framework: Optional framework filter.

        Returns:
            List of dicts with root_cause_id, count, priorities, frameworks.
        """
        query = (
            session.query(
                Issue.root_cause_id,
                func.count(Issue.id).label("count"),
            )
            .filter(
                Issue.root_cause_id.isnot(None),
                Issue.root_cause_id != "",
            )
            .group_by(Issue.root_cause_id)
        )

        if framework:
            query = query.filter(Issue.framework == framework)

        rows = query.all()
        result: list[dict[str, Any]] = []

        for root_cause_id, count in rows:
            # Fetch detail for each group
            issues = session.query(Issue).filter(
                Issue.root_cause_id == root_cause_id,
            )
            if framework:
                issues = issues.filter(Issue.framework == framework)
            issues = issues.all()

            priorities = {}
            frameworks = set()
            for iss in issues:
                pri = iss.priority or "medium"
                priorities[pri] = priorities.get(pri, 0) + 1
                if iss.framework:
                    frameworks.add(iss.framework)

            result.append(
                {
                    "root_cause_id": root_cause_id,
                    "count": count,
                    "priorities": priorities,
                    "frameworks": sorted(frameworks),
                }
            )

        # Sort by count descending
        result.sort(key=lambda r: r["count"], reverse=True)
        return result

    def set_root_cause(
        self,
        session: Session,
        issue_ids: list[str],
        root_cause_id: str,
        actor: str = "",
    ) -> list[Issue]:
        """Link multiple issues to the same root cause.

        Args:
            session: SQLAlchemy session.
            issue_ids: List of issue IDs to link.
            root_cause_id: The root cause identifier.
            actor: Who performed the linking.

        Returns:
            List of updated Issue objects.

        Raises:
            ValueError: If no valid issues found.
        """
        if not root_cause_id:
            raise ValueError("root_cause_id must not be empty")

        issues = session.query(Issue).filter(Issue.id.in_(issue_ids)).all()
        if not issues:
            raise ValueError(f"No issues found for IDs: {issue_ids}")

        now = datetime.now(timezone.utc)
        for issue in issues:
            issue.root_cause_id = root_cause_id
            issue.updated_at = now

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="issues_root_cause_set",
            entity_type="issue",
            entity_id="batch",
            actor=actor or "system",
            metadata={
                "root_cause_id": root_cause_id,
                "issue_ids": [str(i.id) for i in issues],
                "count": len(issues),
            },
        )

        return issues
