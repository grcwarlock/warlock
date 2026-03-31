"""Personnel management with HR + IdP + training cross-reference."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import Finding, Personnel
from warlock.utils import ensure_aware


class PersonnelManager:
    """Cross-references HR, IdP, and training data into unified personnel records."""

    # Flag definitions and their risk weights (0-100 contribution)
    FLAG_WEIGHTS = {
        "terminated_but_active_idp": 30,
        "no_background_check": 15,
        "no_mfa": 25,
        "overdue_training": 10,
        "no_access_review": 10,
        "high_phishing_risk": 10,
    }

    def sync_from_hr(self, session: Session, hr_findings: list[Finding] | None = None) -> dict:
        """Import/update personnel from Workday findings (resource_type=hr_employee).

        Creates new Personnel records or updates existing ones by email match.
        Returns {created: N, updated: N, flagged: N}.
        """
        if hr_findings is None:
            hr_findings = (
                session.query(Finding)
                .filter(Finding.resource_type.in_(["hr_employee", "workday_employee"]))
                .all()
            )

        created = 0
        updated = 0
        now = datetime.now(timezone.utc)

        for finding in hr_findings:
            detail = finding.detail or {}
            email = detail.get("email") or detail.get("work_email")
            if not email:
                continue

            person = session.query(Personnel).filter(Personnel.email == email).first()
            if person is None:
                person = Personnel(
                    email=email,
                    full_name=detail.get("full_name", detail.get("name", email)),
                    is_active=True,
                )
                session.add(person)
                created += 1
            else:
                updated += 1

            # Update HR fields
            person.full_name = detail.get("full_name", detail.get("name", person.full_name))
            person.department = detail.get("department", person.department)
            person.title = detail.get("title", detail.get("job_title", person.title))
            person.manager_email = detail.get("manager_email", person.manager_email)
            person.employee_type = detail.get("employee_type", person.employee_type or "employee")
            person.hr_employee_id = detail.get("employee_id", person.hr_employee_id)

            if detail.get("hire_date"):
                try:
                    person.hire_date = datetime.fromisoformat(str(detail["hire_date"]))
                except (ValueError, TypeError):
                    pass

            if detail.get("termination_date"):
                try:
                    person.termination_date = datetime.fromisoformat(
                        str(detail["termination_date"])
                    )
                except (ValueError, TypeError):
                    pass

            person.hr_status = detail.get("status", detail.get("hr_status", person.hr_status))
            person.background_check_status = detail.get(
                "background_check_status", person.background_check_status
            )
            if detail.get("background_check_date"):
                try:
                    person.background_check_date = datetime.fromisoformat(
                        str(detail["background_check_date"])
                    )
                except (ValueError, TypeError):
                    pass

            if detail.get("agreements_signed"):
                person.agreements_signed = detail["agreements_signed"]

            person.last_synced = now
            person.updated_at = now

        session.flush()

        # Compute flags after sync
        flagged = self.compute_flags(session)
        return {"created": created, "updated": updated, "flagged": flagged}

    def sync_from_idp(self, session: Session, idp_findings: list[Finding] | None = None) -> dict:
        """Cross-reference IdP data (okta_user, entra_user) against personnel records.

        Updates idp_status, mfa_enabled, last_login, groups.
        Flags terminated HR employees still active in IdP.
        """
        if idp_findings is None:
            idp_findings = (
                session.query(Finding)
                .filter(
                    Finding.resource_type.in_(
                        [
                            "okta_user",
                            "entra_user",
                            "google_user",
                            "iam_user",
                            "idp_user",
                        ]
                    )
                )
                .all()
            )

        created = 0
        updated = 0
        now = datetime.now(timezone.utc)

        for finding in idp_findings:
            detail = finding.detail or {}
            email = detail.get("email") or detail.get("user_email") or detail.get("login")
            if not email:
                continue

            person = session.query(Personnel).filter(Personnel.email == email).first()
            if person is None:
                # Create a stub record from IdP data
                person = Personnel(
                    email=email,
                    full_name=detail.get("full_name", detail.get("display_name", email)),
                    is_active=True,
                )
                session.add(person)
                created += 1
            else:
                updated += 1

            person.idp_user_id = detail.get("user_id", detail.get("id", person.idp_user_id))
            person.idp_provider = detail.get("provider", finding.provider) or person.idp_provider
            person.idp_status = detail.get("status", detail.get("idp_status", person.idp_status))

            if detail.get("last_login"):
                try:
                    person.idp_last_login = datetime.fromisoformat(str(detail["last_login"]))
                except (ValueError, TypeError):
                    pass

            if "mfa_enabled" in detail:
                person.mfa_enabled = bool(detail["mfa_enabled"])
            elif "mfa" in detail:
                person.mfa_enabled = bool(detail["mfa"])

            if detail.get("groups"):
                person.idp_groups = detail["groups"]

            person.last_synced = now
            person.updated_at = now

        session.flush()
        flagged = self.compute_flags(session)
        return {"created": created, "updated": updated, "flagged": flagged}

    def sync_from_training(
        self, session: Session, training_findings: list[Finding] | None = None
    ) -> dict:
        """Import training status from KnowBe4 findings.

        Updates training_status, last_training_date, phishing_score.
        """
        if training_findings is None:
            training_findings = (
                session.query(Finding)
                .filter(
                    Finding.resource_type.in_(
                        [
                            "training_enrollment",
                            "phishing_result",
                            "knowbe4_user",
                            "training_completion",
                        ]
                    )
                )
                .all()
            )

        created = 0
        updated = 0
        now = datetime.now(timezone.utc)

        for finding in training_findings:
            detail = finding.detail or {}
            email = detail.get("email") or detail.get("user_email")
            if not email:
                continue

            person = session.query(Personnel).filter(Personnel.email == email).first()
            if person is None:
                person = Personnel(
                    email=email,
                    full_name=detail.get("full_name", detail.get("name", email)),
                    is_active=True,
                )
                session.add(person)
                created += 1
            else:
                updated += 1

            person.training_status = detail.get(
                "training_status", detail.get("status", person.training_status)
            )

            if detail.get("last_training_date") or detail.get("completed_date"):
                date_str = detail.get("last_training_date") or detail.get("completed_date")
                try:
                    person.last_training_date = datetime.fromisoformat(str(date_str))
                except (ValueError, TypeError):
                    pass

            if "phishing_score" in detail:
                try:
                    person.phishing_score = float(detail["phishing_score"])
                except (ValueError, TypeError):
                    pass

            if detail.get("completions") or detail.get("campaign"):
                existing = person.training_completions or []
                if detail.get("campaign"):
                    existing.append(
                        {
                            "campaign": detail["campaign"],
                            "completed_date": detail.get("completed_date", now.isoformat()),
                        }
                    )
                elif detail.get("completions"):
                    existing.extend(detail["completions"])
                person.training_completions = existing

            person.last_synced = now
            person.updated_at = now

        session.flush()
        flagged = self.compute_flags(session)
        return {"created": created, "updated": updated, "flagged": flagged}

    def sync_all(self, session: Session) -> dict:
        """Run all sync operations using current Finding data."""
        hr_result = self.sync_from_hr(session)
        idp_result = self.sync_from_idp(session)
        training_result = self.sync_from_training(session)

        return {
            "hr": hr_result,
            "idp": idp_result,
            "training": training_result,
            "total_personnel": session.query(func.count(Personnel.id)).scalar() or 0,
        }

    def compute_flags(self, session: Session) -> int:
        """Scan all personnel and set compliance flags.

        Flags:
        - terminated_but_active_idp: HR terminated but IdP still active
        - no_background_check: active employee, no background check
        - no_mfa: active IdP account without MFA
        - overdue_training: training status overdue
        - no_access_review: last review > 90 days ago
        - high_phishing_risk: phishing score < 50

        Returns count of flagged personnel.
        """
        people = session.query(Personnel).filter(Personnel.is_active == True).all()  # noqa: E712
        flagged_count = 0
        now = datetime.now(timezone.utc)
        review_threshold = now - timedelta(days=90)

        for person in people:
            flags: list[str] = []

            # Terminated in HR but still active in IdP
            if person.hr_status in ("terminated", "inactive") and person.idp_status in (
                "active",
                "ACTIVE",
            ):
                flags.append("terminated_but_active_idp")

            # Active employee without background check
            if person.hr_status == "active" and person.background_check_status in (
                None,
                "not_started",
                "pending",
            ):
                flags.append("no_background_check")

            # Active IdP account without MFA
            if person.idp_status in ("active", "ACTIVE") and person.mfa_enabled is False:
                flags.append("no_mfa")

            # Overdue training
            if person.training_status == "overdue" or (
                person.training_status is None and person.hr_status == "active"
            ):
                flags.append("overdue_training")

            # No access review in 90 days
            if person.last_access_review is None and person.hr_status == "active":
                flags.append("no_access_review")
            elif person.last_access_review:
                lar = ensure_aware(person.last_access_review)
                if lar < review_threshold:
                    flags.append("no_access_review")

            # High phishing risk
            if person.phishing_score is not None and person.phishing_score < 50:
                flags.append("high_phishing_risk")

            person.flags = flags
            if flags:
                flagged_count += 1

        session.flush()
        self.compute_risk_scores(session)
        return flagged_count

    def compute_risk_scores(self, session: Session) -> None:
        """Calculate risk score per person (0-100) based on flags."""
        people = session.query(Personnel).filter(Personnel.is_active == True).all()  # noqa: E712

        for person in people:
            flags = person.flags or []
            score = 0.0
            for flag in flags:
                score += self.FLAG_WEIGHTS.get(flag, 5)
            person.risk_score = min(score, 100.0)

        session.flush()

    def terminated_with_active_access(self, session: Session) -> list[Personnel]:
        """Critical: employees terminated in HR but still active in IdP."""
        return (
            session.query(Personnel)
            .filter(
                Personnel.hr_status.in_(["terminated", "inactive"]),
                Personnel.idp_status.in_(["active", "ACTIVE"]),
                Personnel.is_active == True,  # noqa: E712
            )
            .order_by(Personnel.termination_date.asc())
            .all()
        )

    def summary(self, session: Session) -> dict:
        """Return personnel stats: total, by status, by department, flagged count."""
        total = (
            session.query(func.count(Personnel.id))
            .filter(
                Personnel.is_active == True  # noqa: E712
            )
            .scalar()
            or 0
        )

        # By HR status
        status_rows = (
            session.query(Personnel.hr_status, func.count(Personnel.id))
            .filter(Personnel.is_active == True)  # noqa: E712
            .group_by(Personnel.hr_status)
            .all()
        )
        by_status = {s or "unknown": c for s, c in status_rows}

        # By department
        dept_rows = (
            session.query(Personnel.department, func.count(Personnel.id))
            .filter(Personnel.is_active == True)  # noqa: E712
            .group_by(Personnel.department)
            .all()
        )
        by_department = {d or "unknown": c for d, c in dept_rows}

        # Flagged count (anyone with non-empty flags list and risk_score > 0)
        flagged = (
            session.query(func.count(Personnel.id))
            .filter(
                Personnel.is_active == True,  # noqa: E712
                Personnel.risk_score > 0,
            )
            .scalar()
            or 0
        )

        # Terminated with active access
        terminated_active = len(self.terminated_with_active_access(session))

        # MFA stats
        no_mfa = (
            session.query(func.count(Personnel.id))
            .filter(
                Personnel.is_active == True,  # noqa: E712
                Personnel.mfa_enabled == False,  # noqa: E712
                Personnel.idp_status.in_(["active", "ACTIVE"]),
            )
            .scalar()
            or 0
        )

        return {
            "total": total,
            "by_status": by_status,
            "by_department": by_department,
            "flagged": flagged,
            "terminated_with_active_access": terminated_active,
            "no_mfa": no_mfa,
        }
