"""Repository pattern — clean data access layer over SQLAlchemy models.

Replaces raw session.query() calls with typed, reusable repository methods.
Each repository encapsulates queries for a specific domain entity.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from warlock.db.models import (
    Attestation,
    AuditComment,
    AuditEngagement,
    AuditEntry,
    ConnectorRun,
    ControlMapping,
    ControlResult,
    DataSilo,
    Finding,
    Issue,
    IssueComment,
    Personnel,
    PostureSnapshot,
    Questionnaire,
    QuestionnaireTemplate,
    SystemProfile,
    User,
)


# ---------------------------------------------------------------------------
# Base Repository
# ---------------------------------------------------------------------------


class BaseRepository:
    """Base repository with common CRUD operations."""

    def __init__(self, session: Session, model_class: type) -> None:
        self.session = session
        self.model = model_class

    def get(self, id: str) -> Any | None:
        """Fetch a single record by primary key."""
        return self.session.query(self.model).filter(self.model.id == id).first()

    def list(self, limit: int = 100, offset: int = 0, **filters: Any) -> list:
        """List records with optional column filters.

        Keyword arguments are treated as equality filters on model columns.
        """
        query = self.session.query(self.model)
        for col, value in filters.items():
            if hasattr(self.model, col) and value is not None:
                query = query.filter(getattr(self.model, col) == value)
        return query.offset(offset).limit(limit).all()

    def count(self, **filters: Any) -> int:
        """Count records matching optional filters."""
        query = self.session.query(func.count(self.model.id))
        for col, value in filters.items():
            if hasattr(self.model, col) and value is not None:
                query = query.filter(getattr(self.model, col) == value)
        return query.scalar() or 0

    def create(self, **kwargs: Any) -> Any:
        """Create and flush a new record."""
        instance = self.model(**kwargs)
        self.session.add(instance)
        self.session.flush()
        return instance

    def update(self, id: str, **kwargs: Any) -> Any | None:
        """Update fields on an existing record. Returns None if not found."""
        instance = self.get(id)
        if instance is None:
            return None
        for key, value in kwargs.items():
            if hasattr(instance, key):
                setattr(instance, key, value)
        self.session.flush()
        return instance

    def delete(self, id: str) -> bool:
        """Soft-delete (set is_active=False) if supported, otherwise hard-delete.

        Returns True if the record existed.
        """
        instance = self.get(id)
        if instance is None:
            return False
        if hasattr(instance, "is_active"):
            instance.is_active = False
            self.session.flush()
        else:
            self.session.delete(instance)
            self.session.flush()
        return True


# ---------------------------------------------------------------------------
# Finding Repository
# ---------------------------------------------------------------------------


class FindingRepository(BaseRepository):
    """Finding-specific queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Finding)

    def by_resource(
        self,
        resource_type: str,
        resource_id: str | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        """Findings for a specific resource type, optionally narrowed to one resource."""
        query = self.session.query(Finding).filter(Finding.resource_type == resource_type)
        if resource_id is not None:
            query = query.filter(Finding.resource_id == resource_id)
        return query.order_by(Finding.observed_at.desc()).limit(limit).all()

    def by_severity(self, severity: str, limit: int = 100) -> list[Finding]:
        """Findings at a given severity level."""
        return (
            self.session.query(Finding)
            .filter(Finding.severity == severity)
            .order_by(Finding.observed_at.desc())
            .limit(limit)
            .all()
        )

    def by_source(
        self,
        source: str,
        provider: str | None = None,
        limit: int = 100,
    ) -> list[Finding]:
        """Findings from a specific source (e.g. 'aws'), optionally filtered by provider."""
        query = self.session.query(Finding).filter(Finding.source == source)
        if provider is not None:
            query = query.filter(Finding.provider == provider)
        return query.order_by(Finding.observed_at.desc()).limit(limit).all()

    def by_date_range(
        self,
        start: datetime,
        end: datetime,
        limit: int = 100,
    ) -> list[Finding]:
        """Findings observed within a date range (inclusive)."""
        return (
            self.session.query(Finding)
            .filter(Finding.observed_at >= start, Finding.observed_at <= end)
            .order_by(Finding.observed_at.desc())
            .limit(limit)
            .all()
        )

    def recent(self, hours: int = 24, limit: int = 100) -> list[Finding]:
        """Findings observed in the last N hours."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return (
            self.session.query(Finding)
            .filter(Finding.observed_at >= cutoff)
            .order_by(Finding.observed_at.desc())
            .limit(limit)
            .all()
        )


# ---------------------------------------------------------------------------
# Control Result Repository
# ---------------------------------------------------------------------------


class ControlResultRepository(BaseRepository):
    """Control result queries with aggregation."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, ControlResult)

    def by_framework(self, framework: str, limit: int = 100) -> list[ControlResult]:
        """All results for a framework."""
        return (
            self.session.query(ControlResult)
            .filter(ControlResult.framework == framework)
            .order_by(ControlResult.assessed_at.desc())
            .limit(limit)
            .all()
        )

    def by_control(self, framework: str, control_id: str) -> list[ControlResult]:
        """All results for a specific control within a framework."""
        return (
            self.session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id == control_id,
            )
            .order_by(ControlResult.assessed_at.desc())
            .all()
        )

    def by_status(
        self,
        status: str,
        framework: str | None = None,
        limit: int = 100,
    ) -> list[ControlResult]:
        """Results filtered by status, optionally within a framework."""
        query = self.session.query(ControlResult).filter(ControlResult.status == status)
        if framework is not None:
            query = query.filter(ControlResult.framework == framework)
        return query.order_by(ControlResult.assessed_at.desc()).limit(limit).all()

    def coverage_summary(self, framework: str | None = None) -> dict[str, Any]:
        """Aggregate status counts, keyed by framework.

        Returns::

            {
                "nist_800_53": {
                    "total": 150,
                    "compliant": 100,
                    "non_compliant": 30,
                    "partial": 10,
                    "not_assessed": 10,
                    "rate": 66.67,
                },
                ...
            }
        """
        query = (
            self.session.query(
                ControlResult.framework,
                ControlResult.status,
                func.count(ControlResult.id),
            )
            .group_by(ControlResult.framework, ControlResult.status)
        )
        if framework is not None:
            query = query.filter(ControlResult.framework == framework)

        fw_stats: dict[str, dict[str, Any]] = {}
        for fw, st, cnt in query.all():
            if fw not in fw_stats:
                fw_stats[fw] = {
                    "total": 0,
                    "compliant": 0,
                    "non_compliant": 0,
                    "partial": 0,
                    "not_assessed": 0,
                }
            fw_stats[fw]["total"] += cnt
            if st in ("compliant", "non_compliant", "partial", "not_assessed"):
                fw_stats[fw][st] += cnt
            else:
                fw_stats[fw]["not_assessed"] += cnt

        for fw, s in fw_stats.items():
            s["rate"] = round(s["compliant"] / s["total"] * 100, 2) if s["total"] > 0 else 0.0

        return fw_stats

    def latest_per_control(self, framework: str) -> list[ControlResult]:
        """Most recent result per control_id within a framework."""
        subq = (
            self.session.query(
                ControlResult.control_id,
                func.max(ControlResult.assessed_at).label("max_assessed"),
            )
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.control_id)
            .subquery()
        )
        return (
            self.session.query(ControlResult)
            .join(
                subq,
                (ControlResult.control_id == subq.c.control_id)
                & (ControlResult.assessed_at == subq.c.max_assessed)
                & (ControlResult.framework == framework),
            )
            .all()
        )


# ---------------------------------------------------------------------------
# Posture Snapshot Repository
# ---------------------------------------------------------------------------


class PostureSnapshotRepository(BaseRepository):
    """Posture trend queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, PostureSnapshot)

    def latest(
        self,
        framework: str,
        control_id: str | None = None,
    ) -> PostureSnapshot | None:
        """Get the latest snapshot for a framework (and optionally a specific control)."""
        query = self.session.query(PostureSnapshot).filter(
            PostureSnapshot.framework == framework
        )
        if control_id is not None:
            query = query.filter(PostureSnapshot.control_id == control_id)
        return query.order_by(PostureSnapshot.snapshot_date.desc()).first()

    def history(
        self,
        framework: str,
        control_id: str,
        days: int = 90,
    ) -> list[PostureSnapshot]:
        """Snapshot history for a specific control over the last N days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        return (
            self.session.query(PostureSnapshot)
            .filter(
                PostureSnapshot.framework == framework,
                PostureSnapshot.control_id == control_id,
                PostureSnapshot.snapshot_date >= cutoff,
            )
            .order_by(PostureSnapshot.snapshot_date.asc())
            .all()
        )

    def trend(self, framework: str, days: int = 30) -> list[dict[str, Any]]:
        """Daily average posture scores for a framework over the last N days.

        Returns a list of dicts: ``[{"date": "2025-06-01", "avg_score": 82.5, "controls": 50}, ...]``
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        rows = (
            self.session.query(
                func.date(PostureSnapshot.snapshot_date).label("day"),
                func.avg(PostureSnapshot.posture_score).label("avg_score"),
                func.count(PostureSnapshot.id).label("controls"),
            )
            .filter(
                PostureSnapshot.framework == framework,
                PostureSnapshot.snapshot_date >= cutoff,
            )
            .group_by(func.date(PostureSnapshot.snapshot_date))
            .order_by(func.date(PostureSnapshot.snapshot_date))
            .all()
        )
        return [
            {
                "date": str(row.day),
                "avg_score": round(float(row.avg_score), 2),
                "controls": int(row.controls),
            }
            for row in rows
        ]


# ---------------------------------------------------------------------------
# User Repository
# ---------------------------------------------------------------------------


class UserRepository(BaseRepository):
    """User queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, User)

    def by_email(self, email: str) -> User | None:
        """Look up a user by email address."""
        return self.session.query(User).filter(User.email == email).first()

    def active_users(self) -> list[User]:
        """All active users."""
        return (
            self.session.query(User)
            .filter(User.is_active == True)  # noqa: E712
            .order_by(User.created_at.desc())
            .all()
        )


# ---------------------------------------------------------------------------
# Audit Engagement Repository
# ---------------------------------------------------------------------------


class AuditEngagementRepository(BaseRepository):
    """Audit engagement queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, AuditEngagement)

    def active_engagements(self) -> list[AuditEngagement]:
        """All engagements with status='active'."""
        return (
            self.session.query(AuditEngagement)
            .filter(AuditEngagement.status == "active")
            .order_by(AuditEngagement.created_at.desc())
            .all()
        )

    def by_framework(self, framework: str) -> list[AuditEngagement]:
        """All engagements for a specific framework."""
        return (
            self.session.query(AuditEngagement)
            .filter(AuditEngagement.framework == framework)
            .order_by(AuditEngagement.created_at.desc())
            .all()
        )


# ---------------------------------------------------------------------------
# Connector Run Repository
# ---------------------------------------------------------------------------


class ConnectorRunRepository(BaseRepository):
    """Connector run queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, ConnectorRun)

    def latest_per_connector(self) -> list[ConnectorRun]:
        """Most recent run per connector (by provider + source_type)."""
        subq = (
            self.session.query(
                ConnectorRun.provider,
                ConnectorRun.source_type,
                func.max(ConnectorRun.started_at).label("max_started"),
            )
            .group_by(ConnectorRun.provider, ConnectorRun.source_type)
            .subquery()
        )
        return (
            self.session.query(ConnectorRun)
            .join(
                subq,
                (ConnectorRun.provider == subq.c.provider)
                & (ConnectorRun.source_type == subq.c.source_type)
                & (ConnectorRun.started_at == subq.c.max_started),
            )
            .all()
        )

    def failed_runs(self, hours: int = 24) -> list[ConnectorRun]:
        """Connector runs that failed in the last N hours."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return (
            self.session.query(ConnectorRun)
            .filter(
                ConnectorRun.status == "error",
                ConnectorRun.started_at >= cutoff,
            )
            .order_by(ConnectorRun.started_at.desc())
            .all()
        )


# ---------------------------------------------------------------------------
# Issue Repository
# ---------------------------------------------------------------------------


class IssueRepository(BaseRepository):
    """Issue tracking queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Issue)

    def by_status(self, status: str, limit: int = 100) -> list[Issue]:
        """Issues filtered by status."""
        return (
            self.session.query(Issue)
            .filter(Issue.status == status)
            .order_by(Issue.created_at.desc())
            .limit(limit)
            .all()
        )

    def by_framework(self, framework: str, limit: int = 100) -> list[Issue]:
        """Issues for a specific framework."""
        return (
            self.session.query(Issue)
            .filter(Issue.framework == framework)
            .order_by(Issue.created_at.desc())
            .limit(limit)
            .all()
        )

    def by_assigned_to(self, assigned_to: str, limit: int = 100) -> list[Issue]:
        """Issues assigned to a specific person."""
        return (
            self.session.query(Issue)
            .filter(Issue.assigned_to == assigned_to)
            .order_by(Issue.created_at.desc())
            .limit(limit)
            .all()
        )

    def overdue(self, limit: int = 100) -> list[Issue]:
        """Issues past their due date that are not closed/accepted."""
        now = datetime.now(timezone.utc)
        return (
            self.session.query(Issue)
            .filter(
                Issue.due_date < now,
                Issue.status.notin_(["closed", "risk_accepted", "verified"]),
            )
            .order_by(Issue.due_date.asc())
            .limit(limit)
            .all()
        )

    def comments_for_issue(self, issue_id: str) -> list[IssueComment]:
        """All comments for an issue."""
        return (
            self.session.query(IssueComment)
            .filter(IssueComment.issue_id == issue_id)
            .order_by(IssueComment.created_at.asc())
            .all()
        )


# ---------------------------------------------------------------------------
# Attestation Repository
# ---------------------------------------------------------------------------


class AttestationRepository(BaseRepository):
    """Attestation queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Attestation)

    def by_engagement(self, engagement_id: str) -> list[Attestation]:
        """Attestations for a specific engagement."""
        return (
            self.session.query(Attestation)
            .filter(Attestation.engagement_id == engagement_id)
            .order_by(Attestation.created_at.desc())
            .all()
        )

    def by_framework(self, framework: str, limit: int = 100) -> list[Attestation]:
        """Attestations for a framework."""
        return (
            self.session.query(Attestation)
            .filter(Attestation.framework == framework)
            .order_by(Attestation.created_at.desc())
            .limit(limit)
            .all()
        )

    def by_status(self, status: str, limit: int = 100) -> list[Attestation]:
        """Attestations filtered by status."""
        return (
            self.session.query(Attestation)
            .filter(Attestation.status == status)
            .order_by(Attestation.created_at.desc())
            .limit(limit)
            .all()
        )


# ---------------------------------------------------------------------------
# System Profile Repository
# ---------------------------------------------------------------------------


class SystemProfileRepository(BaseRepository):
    """System profile queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, SystemProfile)

    def active(self) -> list[SystemProfile]:
        """All active system profiles."""
        return (
            self.session.query(SystemProfile)
            .filter(SystemProfile.is_active == True)  # noqa: E712
            .order_by(SystemProfile.name)
            .all()
        )

    def by_authorization_status(
        self,
        status: str,
        limit: int = 100,
    ) -> list[SystemProfile]:
        """Profiles filtered by authorization status."""
        return (
            self.session.query(SystemProfile)
            .filter(SystemProfile.authorization_status == status)
            .order_by(SystemProfile.name)
            .limit(limit)
            .all()
        )

    def expiring(self, days: int = 90) -> list[SystemProfile]:
        """Profiles with authorization expiring within N days."""
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(days=days)
        return (
            self.session.query(SystemProfile)
            .filter(
                SystemProfile.is_active == True,  # noqa: E712
                SystemProfile.authorization_status == "authorized",
                SystemProfile.authorization_expiry != None,  # noqa: E711
                SystemProfile.authorization_expiry <= cutoff,
            )
            .order_by(SystemProfile.authorization_expiry.asc())
            .all()
        )


# ---------------------------------------------------------------------------
# Personnel Repository
# ---------------------------------------------------------------------------


class PersonnelRepository(BaseRepository):
    """Personnel queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Personnel)

    def by_email(self, email: str) -> Personnel | None:
        """Look up a person by email."""
        return self.session.query(Personnel).filter(Personnel.email == email).first()

    def by_department(self, department: str, limit: int = 100) -> list[Personnel]:
        """Personnel in a specific department."""
        return (
            self.session.query(Personnel)
            .filter(Personnel.department == department, Personnel.is_active == True)  # noqa: E712
            .order_by(Personnel.full_name)
            .limit(limit)
            .all()
        )

    def by_hr_status(self, status: str, limit: int = 100) -> list[Personnel]:
        """Personnel filtered by HR status."""
        return (
            self.session.query(Personnel)
            .filter(Personnel.hr_status == status, Personnel.is_active == True)  # noqa: E712
            .order_by(Personnel.full_name)
            .limit(limit)
            .all()
        )

    def flagged(self, limit: int = 100) -> list[Personnel]:
        """Personnel with risk_score > 0."""
        return (
            self.session.query(Personnel)
            .filter(Personnel.risk_score > 0, Personnel.is_active == True)  # noqa: E712
            .order_by(Personnel.risk_score.desc())
            .limit(limit)
            .all()
        )

    def terminated_with_active_idp(self) -> list[Personnel]:
        """Terminated in HR but active in IdP."""
        return (
            self.session.query(Personnel)
            .filter(
                Personnel.hr_status.in_(["terminated", "inactive"]),
                Personnel.idp_status.in_(["active", "ACTIVE"]),
                Personnel.is_active == True,  # noqa: E712
            )
            .order_by(Personnel.termination_date.asc())
            .all()
        )


# ---------------------------------------------------------------------------
# Questionnaire Repository
# ---------------------------------------------------------------------------


class QuestionnaireTemplateRepository(BaseRepository):
    """Questionnaire template queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, QuestionnaireTemplate)

    def active_templates(self) -> list[QuestionnaireTemplate]:
        """All active templates."""
        return (
            self.session.query(QuestionnaireTemplate)
            .filter(QuestionnaireTemplate.is_active == True)  # noqa: E712
            .order_by(QuestionnaireTemplate.name)
            .all()
        )

    def by_type(self, template_type: str) -> list[QuestionnaireTemplate]:
        """Templates of a specific type."""
        return (
            self.session.query(QuestionnaireTemplate)
            .filter(
                QuestionnaireTemplate.template_type == template_type,
                QuestionnaireTemplate.is_active == True,  # noqa: E712
            )
            .all()
        )


class QuestionnaireRepository(BaseRepository):
    """Questionnaire queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, Questionnaire)

    def by_vendor(self, vendor_name: str, limit: int = 100) -> list[Questionnaire]:
        """Questionnaires for a specific vendor."""
        return (
            self.session.query(Questionnaire)
            .filter(Questionnaire.vendor_name == vendor_name)
            .order_by(Questionnaire.created_at.desc())
            .limit(limit)
            .all()
        )

    def by_status(self, status: str, limit: int = 100) -> list[Questionnaire]:
        """Questionnaires filtered by status."""
        return (
            self.session.query(Questionnaire)
            .filter(Questionnaire.status == status)
            .order_by(Questionnaire.created_at.desc())
            .limit(limit)
            .all()
        )

    def overdue(self, limit: int = 100) -> list[Questionnaire]:
        """Overdue questionnaires."""
        now = datetime.now(timezone.utc)
        return (
            self.session.query(Questionnaire)
            .filter(
                Questionnaire.due_date < now,
                Questionnaire.status.notin_(["completed", "reviewed", "accepted", "rejected"]),
            )
            .order_by(Questionnaire.due_date.asc())
            .limit(limit)
            .all()
        )


# ---------------------------------------------------------------------------
# Data Silo Repository
# ---------------------------------------------------------------------------


class DataSiloRepository(BaseRepository):
    """Data silo queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, DataSilo)

    def by_type(self, silo_type: str, limit: int = 100) -> list[DataSilo]:
        """Silos of a specific type."""
        return (
            self.session.query(DataSilo)
            .filter(DataSilo.silo_type == silo_type, DataSilo.is_active == True)  # noqa: E712
            .order_by(DataSilo.name)
            .limit(limit)
            .all()
        )

    def by_classification(self, classification: str, limit: int = 100) -> list[DataSilo]:
        """Silos at a specific classification level."""
        return (
            self.session.query(DataSilo)
            .filter(
                DataSilo.data_classification == classification,
                DataSilo.is_active == True,  # noqa: E712
            )
            .order_by(DataSilo.name)
            .limit(limit)
            .all()
        )

    def by_provider(self, provider: str, limit: int = 100) -> list[DataSilo]:
        """Silos from a specific cloud provider."""
        return (
            self.session.query(DataSilo)
            .filter(DataSilo.provider == provider, DataSilo.is_active == True)  # noqa: E712
            .order_by(DataSilo.name)
            .limit(limit)
            .all()
        )

    def unclassified(self) -> list[DataSilo]:
        """Silos classified as 'unknown'."""
        return (
            self.session.query(DataSilo)
            .filter(
                DataSilo.data_classification == "unknown",
                DataSilo.is_active == True,  # noqa: E712
            )
            .order_by(DataSilo.created_at.desc())
            .all()
        )

    def unprotected(self) -> list[DataSilo]:
        """Silos missing encryption or logging."""
        return (
            self.session.query(DataSilo)
            .filter(
                DataSilo.is_active == True,  # noqa: E712
                (
                    (DataSilo.encrypted_at_rest == False)  # noqa: E712
                    | (DataSilo.encrypted_at_rest == None)  # noqa: E711
                    | (DataSilo.access_logging_enabled == False)  # noqa: E712
                    | (DataSilo.access_logging_enabled == None)  # noqa: E711
                ),
            )
            .all()
        )

    def containing_pii(self) -> list[DataSilo]:
        """Silos containing PII."""
        return (
            self.session.query(DataSilo)
            .filter(DataSilo.contains_pii == True, DataSilo.is_active == True)  # noqa: E712
            .order_by(DataSilo.name)
            .all()
        )


# ---------------------------------------------------------------------------
# Repository factory
# ---------------------------------------------------------------------------


class Repositories:
    """Pre-initialized repository instances for a session."""

    def __init__(self, session: Session) -> None:
        self.findings = FindingRepository(session)
        self.control_results = ControlResultRepository(session)
        self.posture = PostureSnapshotRepository(session)
        self.users = UserRepository(session)
        self.engagements = AuditEngagementRepository(session)
        self.connector_runs = ConnectorRunRepository(session)
        self.issues = IssueRepository(session)
        self.attestations = AttestationRepository(session)
        self.system_profiles = SystemProfileRepository(session)
        self.personnel = PersonnelRepository(session)
        self.questionnaire_templates = QuestionnaireTemplateRepository(session)
        self.questionnaires = QuestionnaireRepository(session)
        self.data_silos = DataSiloRepository(session)


def get_repos(session: Session) -> Repositories:
    """Create a Repositories bundle for the given session."""
    return Repositories(session)
