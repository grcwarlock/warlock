"""POA&M lifecycle management.

Handles auto-creation from non-compliant control results,
extension workflows with delay tracking, and overdue detection.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import POAM, ControlResult, Finding
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Terminal statuses that should not be considered "open"
_CLOSED_STATUSES = frozenset({"completed", "verified", "closed", "risk_accepted", "cancelled"})

# GAP-034: SLA defaults by severity (days until scheduled_completion)
_SLA_DAYS: dict[str, int] = {
    "critical": 30,
    "high": 60,
    "moderate": 90,
    "low": 180,
}

# W-2: Valid POA&M status transitions
VALID_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"open"},
    "open": {"in_progress"},
    "in_progress": {"remediated"},
    "remediated": {"verified"},
    "verified": {"completed"},
}

# Statuses reachable from any state
_ANY_STATE_TARGETS = {"risk_accepted", "cancelled"}


class POAMManager:
    """Manages POA&M lifecycle: creation, extension, querying."""

    def apply_sla_defaults(self, poam: POAM) -> None:
        """Set ``scheduled_completion`` based on severity if not already set.

        Uses ``_SLA_DAYS`` mapping: critical=30d, high=60d, moderate=90d,
        low=180d.  Unknown severities fall back to 90 days.
        """
        if poam.scheduled_completion is not None:
            return
        severity = (poam.severity or "").lower()
        days = _SLA_DAYS.get(severity, 90)
        poam.scheduled_completion = datetime.now(timezone.utc) + timedelta(days=days)
        log.debug(
            "SLA default: POA&M %s severity=%s -> %d days (due %s)",
            poam.id,
            severity,
            days,
            poam.scheduled_completion.isoformat(),
        )

    def auto_create_from_result(
        self,
        session: Session,
        control_result: ControlResult,
    ) -> POAM | None:
        """Create a draft POA&M if a non-compliant result lacks an open one.

        Checks for an existing open POA&M on the same (framework, control_id).
        If one exists, returns None. Otherwise creates a new draft.

        Args:
            session: SQLAlchemy session.
            control_result: The non-compliant ControlResult.

        Returns:
            Newly created POAM or None if one already exists.
        """
        if control_result.status not in ("non_compliant",):
            return None

        # Check for existing open POA&M
        existing = (
            session.query(POAM)
            .filter(
                POAM.framework == control_result.framework,
                POAM.control_id == control_result.control_id,
                ~POAM.status.in_(_CLOSED_STATUSES),
            )
            .first()
        )
        if existing:
            log.debug(
                "Open POA&M %s already exists for %s/%s",
                existing.id,
                control_result.framework,
                control_result.control_id,
            )
            return None

        # Build weakness description from finding + assertion failures
        weakness_parts: list[str] = []
        if control_result.finding_id:
            finding = session.get(Finding, control_result.finding_id)
            if finding:
                weakness_parts.append(finding.title)
        if control_result.assertion_findings:
            for af in control_result.assertion_findings:
                weakness_parts.append(str(af))

        weakness = "; ".join(weakness_parts) or (
            f"Non-compliant: {control_result.framework}/{control_result.control_id}"
        )

        poam = POAM(
            finding_id=control_result.finding_id,
            control_result_id=control_result.id,
            framework=control_result.framework,
            control_id=control_result.control_id,
            system_profile_id=control_result.system_profile_id,
            weakness_description=weakness,
            severity=control_result.severity,
            status="draft",
        )
        session.add(poam)
        session.flush()

        # GAP-034: apply SLA-based deadline if not explicitly set
        self.apply_sla_defaults(poam)
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="poam_auto_created",
            entity_type="poam",
            entity_id=str(poam.id),
            actor="system",
            metadata={
                "framework": poam.framework,
                "control_id": poam.control_id,
                "severity": poam.severity,
                "control_result_id": str(control_result.id),
                "status": "draft",
            },
        )

        log.info(
            "Auto-created POA&M %s for %s/%s (severity=%s)",
            poam.id,
            poam.framework,
            poam.control_id,
            poam.severity,
        )
        return poam

    def extend(
        self,
        session: Session,
        poam_id: str,
        justification: str,
        new_date: datetime,
        approved_by: str,
    ) -> POAM:
        """Extend a POA&M's scheduled completion date.

        Increments delay_count, appends justification to the audit trail.

        Args:
            session: SQLAlchemy session.
            poam_id: ID of the POA&M to extend.
            justification: Reason for the extension.
            new_date: New scheduled completion date.
            approved_by: Who approved the extension.

        Returns:
            Updated POAM.

        Raises:
            ValueError: If POA&M not found or in a terminal status.
        """
        poam = session.get(POAM, poam_id)
        if not poam:
            raise ValueError(f"POA&M not found: {poam_id}")
        if poam.status in _CLOSED_STATUSES:
            raise ValueError(f"Cannot extend POA&M {poam_id} in status '{poam.status}'")

        # Reject past dates — extensions must be into the future
        now = datetime.now(timezone.utc)
        if new_date <= now:
            raise ValueError(
                f"Cannot extend POA&M {poam_id} to a past or current date: {new_date.isoformat()}"
            )

        poam.delay_count = (poam.delay_count or 0) + 1

        justifications = list(poam.delay_justifications or [])
        justifications.append(
            {
                "date": datetime.now(timezone.utc).isoformat(),
                "justification": justification,
                "approved_by": approved_by,
            }
        )
        poam.delay_justifications = justifications
        poam.scheduled_completion = new_date
        poam.updated_by = approved_by

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="poam_extended",
            entity_type="poam",
            entity_id=str(poam.id),
            actor=approved_by,
            metadata={
                "justification": justification,
                "new_scheduled_completion": new_date.isoformat(),
                "delay_count": poam.delay_count,
                "approved_by": approved_by,
            },
        )

        log.info(
            "Extended POA&M %s to %s (delay #%d, approved by %s)",
            poam_id,
            new_date.isoformat(),
            poam.delay_count,
            approved_by,
        )
        return poam

    def transition(
        self,
        session: Session,
        poam_id: str,
        new_status: str,
        actor: str = "",
    ) -> POAM:
        """Transition a POA&M to a new status with validation.

        Args:
            session: SQLAlchemy session.
            poam_id: ID of the POA&M.
            new_status: Target status.
            actor: Who performed the transition.

        Returns:
            Updated POAM.

        Raises:
            ValueError: If POA&M not found or transition is invalid.
        """
        poam = session.get(POAM, poam_id)
        if not poam:
            raise ValueError(f"POA&M not found: {poam_id}")

        # Allow any-state targets
        if new_status in _ANY_STATE_TARGETS:
            old_status = poam.status
            poam.status = new_status
            poam.updated_by = actor
            if new_status == "risk_accepted":
                poam.actual_completion = datetime.now(timezone.utc)
            session.flush()

            audit = AuditTrail(session)
            audit.record(
                action=f"poam_transition_{new_status}",
                entity_type="poam",
                entity_id=str(poam.id),
                actor=actor or "system",
                metadata={"old_status": old_status, "new_status": new_status},
            )

            log.info(
                "POA&M %s transitioned %s -> %s by %s",
                poam_id,
                old_status,
                new_status,
                actor,
            )
            return poam

        allowed = VALID_TRANSITIONS.get(poam.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Cannot transition POA&M from '{poam.status}' to '{new_status}'. "
                f"Allowed transitions: {allowed | _ANY_STATE_TARGETS}"
            )

        old_status = poam.status
        now = datetime.now(timezone.utc)
        poam.status = new_status
        poam.updated_by = actor
        if new_status == "completed":
            poam.actual_completion = now
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action=f"poam_transition_{new_status}",
            entity_type="poam",
            entity_id=str(poam.id),
            actor=actor or "system",
            metadata={"old_status": old_status, "new_status": new_status},
        )

        log.info(
            "POA&M %s transitioned %s -> %s by %s",
            poam_id,
            old_status,
            new_status,
            actor,
        )
        return poam

    def list_poams(
        self,
        session: Session,
        framework: str | None = None,
        status: str | None = None,
        overdue: bool = False,
    ) -> list[POAM]:
        """List POA&Ms with optional filters.

        Args:
            session: SQLAlchemy session.
            framework: Filter by framework.
            status: Filter by status.
            overdue: If True, only return overdue POA&Ms.

        Returns:
            List of matching POAM rows.
        """
        query = session.query(POAM)

        if framework:
            query = query.filter(POAM.framework == framework)
        if status:
            query = query.filter(POAM.status == status)
        if overdue:
            now = datetime.now(timezone.utc)
            query = query.filter(
                POAM.scheduled_completion < now,
                ~POAM.status.in_(_CLOSED_STATUSES),
            )

        return query.order_by(POAM.scheduled_completion).all()

    def get_overdue(self, session: Session) -> list[POAM]:
        """Return all POA&Ms past their scheduled completion that are still open.

        Returns:
            List of overdue POAM rows, ordered by scheduled completion.
        """
        now = datetime.now(timezone.utc)
        poams = (
            session.query(POAM)
            .filter(
                POAM.scheduled_completion.isnot(None),
                ~POAM.status.in_(_CLOSED_STATUSES),
            )
            .order_by(POAM.scheduled_completion)
            .all()
        )
        # W-4: ensure_aware before comparing scheduled_completion
        return [p for p in poams if ensure_aware(p.scheduled_completion) < now]

    # ------------------------------------------------------------------
    # POAM-1: Cost tracking
    # ------------------------------------------------------------------

    def update_cost(
        self,
        session: Session,
        poam_id: str,
        cost_estimate: float | None = None,
        resource_allocation: str | None = None,
        actor: str = "",
    ) -> POAM:
        """Update cost estimate and/or resource allocation on a POA&M.

        Args:
            session: SQLAlchemy session.
            poam_id: ID of the POA&M.
            cost_estimate: Estimated remediation cost in USD.
            resource_allocation: Description of allocated resources.
            actor: Who performed the update.

        Returns:
            Updated POAM.

        Raises:
            ValueError: If POA&M not found.
        """
        poam = session.get(POAM, poam_id)
        if not poam:
            raise ValueError(f"POA&M not found: {poam_id}")

        changes: dict[str, object] = {}

        if cost_estimate is not None:
            changes["old_cost_estimate"] = poam.cost_estimate
            poam.cost_estimate = cost_estimate
            changes["new_cost_estimate"] = cost_estimate

        if resource_allocation is not None:
            changes["old_resource_allocation"] = poam.resource_allocation
            poam.resource_allocation = resource_allocation
            changes["new_resource_allocation"] = resource_allocation

        poam.updated_by = actor or "system"
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="poam_cost_updated",
            entity_type="poam",
            entity_id=str(poam.id),
            actor=actor or "system",
            metadata=changes,
        )

        log.info(
            "Updated cost for POA&M %s: estimate=%s, allocation=%s",
            poam_id,
            cost_estimate,
            resource_allocation,
        )
        return poam

    def cost_summary(
        self,
        session: Session,
        framework: str | None = None,
    ) -> list[dict[str, object]]:
        """Aggregate cost estimates by framework and status.

        Args:
            session: SQLAlchemy session.
            framework: Optional framework filter.

        Returns:
            List of dicts with framework, status, count, total_cost.
        """
        from sqlalchemy import func

        query = session.query(
            POAM.framework,
            POAM.status,
            func.count(POAM.id).label("count"),
            func.coalesce(func.sum(POAM.cost_estimate), 0.0).label("total_cost"),
        ).group_by(POAM.framework, POAM.status)

        if framework:
            query = query.filter(POAM.framework == framework)

        rows = query.all()
        return [
            {
                "framework": row.framework,
                "status": row.status,
                "count": row.count,
                "total_cost": float(row.total_cost),
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # POAM-3: Overdue / escalation helpers
    # ------------------------------------------------------------------

    def check_overdue(self, session: Session) -> list[POAM]:
        """Find POA&Ms past scheduled_completion that are not in a terminal status.

        This is used by the EscalationManager to determine which POA&Ms need
        escalation notifications.

        Returns:
            List of overdue POAM rows with ensure_aware applied.
        """
        return self.get_overdue(session)

    def get_overdue_summary(
        self,
        session: Session,
    ) -> dict[str, dict[str, int]]:
        """Count overdue POA&Ms grouped by severity and framework.

        Returns:
            Dict with 'by_severity' and 'by_framework' sub-dicts mapping
            to counts.
        """
        overdue = self.get_overdue(session)
        by_severity: dict[str, int] = {}
        by_framework: dict[str, int] = {}

        for p in overdue:
            sev = p.severity or "unknown"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            fw = p.framework or "unknown"
            by_framework[fw] = by_framework.get(fw, 0) + 1

        return {
            "total": len(overdue),
            "by_severity": by_severity,
            "by_framework": by_framework,
        }

    # ------------------------------------------------------------------
    # POAM-2: Dependencies
    # ------------------------------------------------------------------

    def add_dependency(
        self,
        session: Session,
        poam_id: str,
        depends_on_poam_id: str,
        actor: str = "",
    ) -> POAM:
        """Record that *poam_id* depends on *depends_on_poam_id*.

        Dependencies are stored in the milestones JSON array as entries
        with ``"type": "dependency"``.

        Args:
            session: SQLAlchemy session.
            poam_id: The POA&M that has the dependency.
            depends_on_poam_id: The POA&M it depends on.
            actor: Who recorded the dependency.

        Returns:
            Updated POAM.

        Raises:
            ValueError: If either POA&M is not found, or self-dependency.
        """
        if poam_id == depends_on_poam_id:
            raise ValueError("A POA&M cannot depend on itself")

        poam = session.get(POAM, poam_id)
        if not poam:
            raise ValueError(f"POA&M not found: {poam_id}")

        dep_poam = session.get(POAM, depends_on_poam_id)
        if not dep_poam:
            raise ValueError(f"Dependent POA&M not found: {depends_on_poam_id}")

        milestones = list(poam.milestones or [])

        # Check for duplicate dependency
        for ms in milestones:
            if (
                ms.get("type") == "dependency"
                and ms.get("depends_on_poam_id") == depends_on_poam_id
            ):
                log.debug("Dependency %s -> %s already exists", poam_id, depends_on_poam_id)
                return poam

        milestones.append(
            {
                "type": "dependency",
                "depends_on_poam_id": depends_on_poam_id,
                "depends_on_framework": dep_poam.framework,
                "depends_on_control_id": dep_poam.control_id,
                "recorded_by": actor or "system",
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        poam.milestones = milestones
        poam.updated_by = actor or "system"
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="poam_dependency_added",
            entity_type="poam",
            entity_id=str(poam.id),
            actor=actor or "system",
            metadata={
                "depends_on_poam_id": depends_on_poam_id,
                "depends_on_framework": dep_poam.framework,
                "depends_on_control_id": dep_poam.control_id,
            },
        )

        log.info("Added dependency: POA&M %s depends on %s", poam_id, depends_on_poam_id)
        return poam

    def get_dependencies(self, session: Session, poam_id: str) -> list[dict[str, str]]:
        """List dependencies for a POA&M.

        Args:
            session: SQLAlchemy session.
            poam_id: ID of the POA&M.

        Returns:
            List of dependency dicts from the milestones JSON.

        Raises:
            ValueError: If POA&M not found.
        """
        poam = session.get(POAM, poam_id)
        if not poam:
            raise ValueError(f"POA&M not found: {poam_id}")

        milestones = list(poam.milestones or [])
        return [ms for ms in milestones if ms.get("type") == "dependency"]

    def check_dependency_conflicts(self, session: Session, poam_id: str) -> list[dict[str, object]]:
        """Check if any POA&Ms this one depends on are still open.

        Args:
            session: SQLAlchemy session.
            poam_id: ID of the POA&M to check.

        Returns:
            List of conflict dicts with dependency info and current status.

        Raises:
            ValueError: If POA&M not found.
        """
        deps = self.get_dependencies(session, poam_id)
        conflicts: list[dict[str, object]] = []

        for dep in deps:
            dep_id = dep.get("depends_on_poam_id", "")
            dep_poam = session.get(POAM, dep_id)
            if not dep_poam:
                conflicts.append(
                    {
                        "depends_on_poam_id": dep_id,
                        "status": "missing",
                        "warning": "Dependent POA&M no longer exists",
                    }
                )
                continue

            if dep_poam.status not in _CLOSED_STATUSES:
                conflicts.append(
                    {
                        "depends_on_poam_id": dep_id,
                        "framework": dep_poam.framework,
                        "control_id": dep_poam.control_id,
                        "status": dep_poam.status,
                        "warning": f"Dependent POA&M is still in '{dep_poam.status}' status",
                    }
                )

        return conflicts

    # ------------------------------------------------------------------
    # POAM-4: Bulk operations
    # ------------------------------------------------------------------

    def bulk_update_status(
        self,
        session: Session,
        new_status: str,
        actor: str,
        framework: str | None = None,
        severity: str | None = None,
        poam_ids: list[str] | None = None,
    ) -> list[POAM]:
        """Batch-update status for multiple POA&Ms filtered by framework/severity.

        Uses the transition() method for each POA&M so status validation
        is enforced.  POA&Ms that cannot transition are skipped with a
        warning log.

        Args:
            session: SQLAlchemy session.
            new_status: Target status.
            actor: Who performed the update.
            framework: Optional framework filter.
            severity: Optional severity filter.
            poam_ids: Optional explicit list of POA&M IDs.

        Returns:
            List of successfully transitioned POAMs.
        """
        query = session.query(POAM).filter(~POAM.status.in_(_CLOSED_STATUSES))

        if framework:
            query = query.filter(POAM.framework == framework)
        if severity:
            query = query.filter(POAM.severity == severity)
        if poam_ids:
            query = query.filter(POAM.id.in_(poam_ids))

        candidates = query.all()
        updated: list[POAM] = []

        for poam in candidates:
            try:
                self.transition(session, str(poam.id), new_status, actor=actor)
                updated.append(poam)
            except ValueError as exc:
                log.warning("Skipping POA&M %s during bulk update: %s", poam.id, exc)

        log.info(
            "Bulk status update to '%s': %d/%d POA&Ms updated by %s",
            new_status,
            len(updated),
            len(candidates),
            actor,
        )
        return updated

    def bulk_assign(
        self,
        session: Session,
        assigned_to: str,
        actor: str,
        framework: str | None = None,
        severity: str | None = None,
        poam_ids: list[str] | None = None,
    ) -> list[POAM]:
        """Batch-assign POA&Ms to a user.

        Args:
            session: SQLAlchemy session.
            assigned_to: User to assign POA&Ms to.
            actor: Who performed the assignment.
            framework: Optional framework filter.
            severity: Optional severity filter.
            poam_ids: Optional explicit list of POA&M IDs.

        Returns:
            List of assigned POAMs.
        """
        query = session.query(POAM).filter(~POAM.status.in_(_CLOSED_STATUSES))

        if framework:
            query = query.filter(POAM.framework == framework)
        if severity:
            query = query.filter(POAM.severity == severity)
        if poam_ids:
            query = query.filter(POAM.id.in_(poam_ids))

        poams = query.all()
        for poam in poams:
            poam.updated_by = assigned_to

        session.flush()

        if poams:
            audit = AuditTrail(session)
            audit.record(
                action="poam_bulk_assigned",
                entity_type="poam",
                entity_id="batch",
                actor=actor,
                metadata={
                    "assigned_to": assigned_to,
                    "count": len(poams),
                    "framework": framework,
                    "severity": severity,
                },
            )

        log.info(
            "Bulk assigned %d POA&Ms to %s by %s",
            len(poams),
            assigned_to,
            actor,
        )
        return poams
