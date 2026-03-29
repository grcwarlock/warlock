"""Employee Lifecycle Automation.

Manages hire/termination lifecycle events:
  - On hire: assign training, send policies, trigger access provisioning
  - On termination: revoke access, reassign assets, archive data
  - Full audit trail of lifecycle events
  - Wire to HRIS connector data (existing personnel records)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import Personnel
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# Lifecycle event types
_EVENT_TYPES = (
    "hire",
    "termination",
    "transfer",
    "promotion",
    "leave_start",
    "leave_end",
    "role_change",
)

# Default onboarding checklist
_ONBOARDING_CHECKLIST = [
    {"task": "background_check", "description": "Initiate background check", "required": True},
    {
        "task": "nda_signed",
        "description": "Sign NDA and confidentiality agreement",
        "required": True,
    },
    {"task": "aup_signed", "description": "Sign acceptable use policy", "required": True},
    {
        "task": "security_training",
        "description": "Complete security awareness training",
        "required": True,
    },
    {"task": "idp_provisioned", "description": "Provision IdP account (SSO/MFA)", "required": True},
    {
        "task": "access_granted",
        "description": "Grant role-based access per department",
        "required": True,
    },
    {"task": "equipment_assigned", "description": "Assign laptop and equipment", "required": False},
    {
        "task": "manager_intro",
        "description": "Manager introduction and team onboarding",
        "required": False,
    },
]

# Default offboarding checklist
_OFFBOARDING_CHECKLIST = [
    {"task": "idp_disabled", "description": "Disable IdP account immediately", "required": True},
    {"task": "access_revoked", "description": "Revoke all system access", "required": True},
    {
        "task": "email_forwarded",
        "description": "Set up email forwarding to manager",
        "required": True,
    },
    {
        "task": "equipment_returned",
        "description": "Collect all company equipment",
        "required": True,
    },
    {
        "task": "data_archived",
        "description": "Archive employee data per retention policy",
        "required": True,
    },
    {
        "task": "assets_reassigned",
        "description": "Reassign owned assets to manager",
        "required": True,
    },
    {"task": "exit_interview", "description": "Conduct exit interview", "required": False},
    {
        "task": "final_access_review",
        "description": "Confirm zero residual access",
        "required": True,
    },
]


class EmployeeLifecycleManager:
    """Manages employee lifecycle events with compliance-aware automation."""

    # ------------------------------------------------------------------
    # On hire
    # ------------------------------------------------------------------

    def on_hire(
        self,
        session: Session,
        email: str,
        full_name: str,
        *,
        department: str | None = None,
        title: str | None = None,
        manager_email: str | None = None,
        employee_type: str = "employee",
        actor: str = "system",
    ) -> dict:
        """Process a new hire lifecycle event.

        Creates or updates the personnel record and generates an
        onboarding checklist with required tasks.

        Args:
            session: SQLAlchemy session.
            email: Employee email address.
            full_name: Employee full name.
            department: Department.
            title: Job title.
            manager_email: Manager's email.
            employee_type: employee, contractor, vendor, intern.
            actor: Who processed the hire.

        Returns:
            Dict with personnel_id, checklist, and event details.
        """
        now = datetime.now(timezone.utc)

        # Find or create personnel record
        person = session.query(Personnel).filter(Personnel.email == email).first()
        if person:
            # Rehire scenario
            person.is_active = True
            person.hr_status = "active"
            person.termination_date = None
            person.full_name = full_name
            log.info("Rehire detected for %s", email)
        else:
            person = Personnel(
                email=email,
                full_name=full_name,
                is_active=True,
                hr_status="active",
            )
            session.add(person)

        person.department = department or person.department
        person.title = title or person.title
        person.manager_email = manager_email or person.manager_email
        person.employee_type = employee_type
        person.hire_date = now
        person.last_synced = now

        session.flush()

        # Generate onboarding checklist
        checklist = []
        for item in _ONBOARDING_CHECKLIST:
            checklist.append(
                {
                    "id": str(uuid4()),
                    "task": item["task"],
                    "description": item["description"],
                    "required": item["required"],
                    "status": "pending",
                    "completed_at": None,
                    "completed_by": None,
                }
            )

        event = {
            "event_id": str(uuid4()),
            "event_type": "hire",
            "personnel_id": person.id,
            "email": email,
            "full_name": full_name,
            "department": department,
            "title": title,
            "manager_email": manager_email,
            "employee_type": employee_type,
            "timestamp": now.isoformat(),
            "checklist": checklist,
            "checklist_total": len(checklist),
            "checklist_required": sum(1 for c in checklist if c["required"]),
        }

        audit = AuditTrail(session)
        audit.record(
            action="employee_hired",
            entity_type="personnel",
            entity_id=person.id,
            actor=actor,
            metadata={
                "email": email,
                "full_name": full_name,
                "department": department,
                "title": title,
                "employee_type": employee_type,
                "checklist_items": len(checklist),
            },
        )

        log.info(
            "Employee hired: %s (%s) — %d onboarding tasks",
            full_name,
            email,
            len(checklist),
        )
        return event

    # ------------------------------------------------------------------
    # On termination
    # ------------------------------------------------------------------

    def on_termination(
        self,
        session: Session,
        email: str,
        *,
        reason: str = "voluntary",
        effective_date: datetime | None = None,
        actor: str = "system",
    ) -> dict:
        """Process an employee termination lifecycle event.

        Updates the personnel record and generates an offboarding
        checklist with required access revocation tasks.

        Args:
            session: SQLAlchemy session.
            email: Employee email address.
            reason: Termination reason (voluntary, involuntary, end_of_contract).
            effective_date: When termination is effective (defaults to now).
            actor: Who processed the termination.

        Returns:
            Dict with personnel_id, checklist, and event details.

        Raises:
            ValueError: If personnel record not found.
        """
        now = datetime.now(timezone.utc)
        effective = effective_date or now

        person = session.query(Personnel).filter(Personnel.email == email).first()
        if not person:
            raise ValueError(f"Personnel record not found for: {email}")

        person.is_active = False
        person.hr_status = "terminated"
        person.termination_date = effective
        person.last_synced = now

        # Flag for access review
        flags = list(person.flags or [])
        if "terminated_but_active_idp" not in flags and person.idp_status == "active":
            flags.append("terminated_but_active_idp")
            person.flags = flags

        session.flush()

        # Generate offboarding checklist
        checklist = []
        for item in _OFFBOARDING_CHECKLIST:
            checklist.append(
                {
                    "id": str(uuid4()),
                    "task": item["task"],
                    "description": item["description"],
                    "required": item["required"],
                    "status": "pending",
                    "completed_at": None,
                    "completed_by": None,
                }
            )

        event = {
            "event_id": str(uuid4()),
            "event_type": "termination",
            "personnel_id": person.id,
            "email": email,
            "full_name": person.full_name,
            "department": person.department,
            "reason": reason,
            "effective_date": effective.isoformat(),
            "timestamp": now.isoformat(),
            "checklist": checklist,
            "checklist_total": len(checklist),
            "checklist_required": sum(1 for c in checklist if c["required"]),
            "flags": list(person.flags or []),
        }

        audit = AuditTrail(session)
        audit.record(
            action="employee_terminated",
            entity_type="personnel",
            entity_id=person.id,
            actor=actor,
            metadata={
                "email": email,
                "full_name": person.full_name,
                "reason": reason,
                "effective_date": effective.isoformat(),
                "flags": list(person.flags or []),
                "checklist_items": len(checklist),
            },
        )

        log.info(
            "Employee terminated: %s (%s) — reason=%s, %d offboarding tasks",
            person.full_name,
            email,
            reason,
            len(checklist),
        )
        return event

    # ------------------------------------------------------------------
    # Track lifecycle events
    # ------------------------------------------------------------------

    def get_lifecycle_summary(
        self,
        session: Session,
        email: str,
    ) -> dict:
        """Get a lifecycle summary for a personnel record.

        Args:
            session: SQLAlchemy session.
            email: Employee email address.

        Returns:
            Dict with personnel info and lifecycle status.

        Raises:
            ValueError: If personnel record not found.
        """
        person = session.query(Personnel).filter(Personnel.email == email).first()
        if not person:
            raise ValueError(f"Personnel record not found for: {email}")

        return {
            "personnel_id": person.id,
            "email": person.email,
            "full_name": person.full_name,
            "department": person.department or "N/A",
            "title": person.title or "N/A",
            "manager_email": person.manager_email or "N/A",
            "employee_type": person.employee_type or "employee",
            "is_active": person.is_active,
            "hr_status": person.hr_status or "unknown",
            "idp_status": person.idp_status or "unknown",
            "mfa_enabled": person.mfa_enabled,
            "hire_date": (
                ensure_aware(person.hire_date).isoformat() if person.hire_date else "N/A"
            ),
            "termination_date": (
                ensure_aware(person.termination_date).isoformat()
                if person.termination_date
                else "N/A"
            ),
            "training_status": person.training_status or "not_enrolled",
            "last_access_review": (
                ensure_aware(person.last_access_review).isoformat()
                if person.last_access_review
                else "N/A"
            ),
            "flags": list(person.flags or []),
            "risk_score": person.risk_score or 0.0,
        }

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    def sync_from_hris(
        self,
        session: Session,
        *,
        actor: str = "system",
    ) -> dict:
        """Sync lifecycle events from HRIS connector findings.

        Reads personnel findings (resource_type=hr_employee) and processes
        hire/termination events based on status changes.

        Args:
            session: SQLAlchemy session.
            actor: Who initiated the sync.

        Returns:
            Dict with hires, terminations, and unchanged counts.
        """
        from warlock.db.models import Finding

        hr_findings = (
            session.query(Finding)
            .filter(Finding.resource_type.in_(["hr_employee", "workday_employee"]))
            .all()
        )

        hires = 0
        terminations = 0
        unchanged = 0

        for finding in hr_findings:
            detail = finding.detail or {}
            email = detail.get("email") or detail.get("work_email")
            if not email:
                continue

            status = detail.get("status", "active").lower()
            full_name = detail.get("full_name", detail.get("name", email))

            person = session.query(Personnel).filter(Personnel.email == email).first()

            if status in ("active", "hired"):
                if not person or not person.is_active:
                    self.on_hire(
                        session=session,
                        email=email,
                        full_name=full_name,
                        department=detail.get("department"),
                        title=detail.get("title", detail.get("job_title")),
                        manager_email=detail.get("manager_email"),
                        employee_type=detail.get("employee_type", "employee"),
                        actor=actor,
                    )
                    hires += 1
                else:
                    unchanged += 1

            elif status in ("terminated", "inactive", "offboarded"):
                if person and person.is_active:
                    self.on_termination(
                        session=session,
                        email=email,
                        reason=detail.get("termination_reason", "voluntary"),
                        actor=actor,
                    )
                    terminations += 1
                else:
                    unchanged += 1
            else:
                unchanged += 1

        log.info(
            "HRIS sync: %d hires, %d terminations, %d unchanged",
            hires,
            terminations,
            unchanged,
        )
        return {
            "hires": hires,
            "terminations": terminations,
            "unchanged": unchanged,
            "total_processed": len(hr_findings),
        }
