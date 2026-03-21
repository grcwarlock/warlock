"""Repository pattern — clean data access layer over SQLAlchemy models.

Replaces raw session.query() calls with typed, reusable repository methods.
Each repository encapsulates queries for a specific domain entity.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from warlock.db.models import (
    APIKey,
    Attestation,
    AuditEngagement,
    AuditEntry,
    ComplianceDrift,
    ConnectorRun,
    ControlMapping,
    ControlResult,
    DataSilo,
    Finding,
    Issue,
    IssueComment,
    LegalHold,
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

    def list_filtered(
        self,
        *,
        scope_filter: Any = None,
        framework: str | None = None,
        severity: str | None = None,
        observation_type: str | None = None,
        source: str | None = None,
        provider: str | None = None,
        resource_type: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        """Filtered finding list with total count.  Returns (rows, total).

        ``scope_filter`` is an optional callable ``(query, model) -> query``
        that applies ABAC scope restrictions.
        """
        query = self.session.query(Finding)
        if scope_filter is not None:
            query = scope_filter(query, Finding)
        if framework:
            query = (
                query.join(ControlMapping, ControlMapping.finding_id == Finding.id)
                .filter(ControlMapping.framework == framework)
                .distinct()
            )
        if severity:
            query = query.filter(Finding.severity == severity)
        if observation_type:
            query = query.filter(Finding.observation_type == observation_type)
        if source:
            query = query.filter(Finding.source == source)
        if provider:
            query = query.filter(Finding.provider == provider)
        if resource_type:
            query = query.filter(Finding.resource_type == resource_type)
        if date_from:
            query = query.filter(Finding.observed_at >= date_from)
        if date_to:
            query = query.filter(Finding.observed_at <= date_to)
        total = query.count()
        rows = query.order_by(Finding.observed_at.desc()).offset(offset).limit(limit).all()
        return rows, total

    def get_scoped(
        self,
        finding_id: str,
        scope_filter: Any = None,
    ) -> Finding | None:
        """Fetch a single finding with optional ABAC scope filter."""
        query = self.session.query(Finding)
        if scope_filter is not None:
            query = scope_filter(query, Finding)
        return query.filter(Finding.id == finding_id).first()


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
        query = self.session.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id),
        ).group_by(ControlResult.framework, ControlResult.status)
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

    def list_filtered(
        self,
        *,
        scope_filter: Any = None,
        framework: str | None = None,
        control_id: str | None = None,
        result_status: str | None = None,
        severity: str | None = None,
        assessor: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
        escape_like_fn: Any = None,
    ) -> tuple[list[ControlResult], int]:
        """Filtered control result list with total count.  Returns (rows, total).

        ``scope_filter`` is an optional callable ``(query, model) -> query``
        for ABAC scope restrictions.  ``escape_like_fn`` escapes LIKE wildcards.
        """
        query = self.session.query(ControlResult)
        if scope_filter is not None:
            query = scope_filter(query, ControlResult)
        if framework:
            query = query.filter(ControlResult.framework == framework)
        if control_id:
            query = query.filter(ControlResult.control_id == control_id)
        if result_status:
            query = query.filter(ControlResult.status == result_status)
        if severity:
            query = query.filter(ControlResult.severity == severity)
        if assessor:
            escaped = escape_like_fn(assessor) if escape_like_fn else assessor
            query = query.filter(ControlResult.assessor.ilike(f"%{escaped}%"))
        if date_from:
            query = query.filter(ControlResult.assessed_at >= date_from)
        if date_to:
            query = query.filter(ControlResult.assessed_at <= date_to)
        total = query.count()
        rows = query.order_by(ControlResult.assessed_at.desc()).offset(offset).limit(limit).all()
        return rows, total

    def coverage_by_status(
        self,
        *,
        scope_filter: Any = None,
        framework: str | None = None,
    ) -> list[tuple[str, str, int]]:
        """Aggregate status counts grouped by (framework, status).

        Returns list of (framework, status, count) tuples.
        ``scope_filter`` applies ABAC restrictions before aggregation.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("coverage_by_status"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.coverage_by_status(framework)
            finally:
                readers.close()
        query = self.session.query(ControlResult)
        if scope_filter is not None:
            query = scope_filter(query, ControlResult)
        query = query.with_entities(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id),
        ).group_by(ControlResult.framework, ControlResult.status)
        if framework:
            query = query.filter(ControlResult.framework == framework)
        return query.all()

    def distinct_frameworks(self) -> list[str]:
        """Return a list of distinct framework names that have control results."""
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("distinct_frameworks"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.distinct_frameworks()
            finally:
                readers.close()
        rows = self.session.query(distinct(ControlResult.framework)).all()
        return [fw for (fw,) in rows]

    def dashboard_framework_summary(self) -> list[tuple[str, str, int]]:
        """Per-framework status counts for dashboard.

        Returns list of (framework, status, count) tuples.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("dashboard_framework_summary"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.dashboard_framework_summary()
            finally:
                readers.close()
        return (
            self.session.query(
                ControlResult.framework,
                ControlResult.status,
                func.count(ControlResult.id).label("cnt"),
            )
            .group_by(ControlResult.framework, ControlResult.status)
            .all()
        )

    def top_non_compliant_risks(self) -> list[Any]:
        """Non-compliant controls grouped by (framework, control_id, severity).

        Returns list of rows with .framework, .control_id, .severity, .cnt attrs.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("top_non_compliant_risks"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.top_non_compliant_risks()
            finally:
                readers.close()
        return (
            self.session.query(
                ControlResult.framework,
                ControlResult.control_id,
                ControlResult.severity,
                func.count(ControlResult.id).label("cnt"),
            )
            .filter(ControlResult.status == "non_compliant")
            .group_by(ControlResult.framework, ControlResult.control_id, ControlResult.severity)
            .all()
        )

    def last_assessed_at(self) -> datetime | None:
        """Timestamp of the most recent control result assessment."""
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("last_assessed_at"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.last_assessed_at()
            finally:
                readers.close()
        row = (
            self.session.query(ControlResult.assessed_at)
            .order_by(ControlResult.assessed_at.desc())
            .first()
        )
        return row.assessed_at if row else None


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
        query = self.session.query(PostureSnapshot).filter(PostureSnapshot.framework == framework)
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

    def latest_snapshot_date(self) -> datetime | None:
        """Return the most recent snapshot_date across all snapshots."""
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("latest_snapshot_date"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.latest_snapshot_date()
            finally:
                readers.close()
        return self.session.query(func.max(PostureSnapshot.snapshot_date)).scalar()

    def list_latest_posture(
        self,
        *,
        scope_filter: Any = None,
        framework: str | None = None,
        control_id: str | None = None,
        latest_date: Any = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[PostureSnapshot]:
        """Posture snapshots filtered to the latest snapshot date.

        ``scope_filter`` is an optional callable ``(query, model) -> query``.
        """
        query = self.session.query(PostureSnapshot)
        if scope_filter is not None:
            query = scope_filter(query, PostureSnapshot)
        if framework:
            query = query.filter(PostureSnapshot.framework == framework)
        if control_id:
            query = query.filter(PostureSnapshot.control_id == control_id)
        if latest_date is not None:
            query = query.filter(PostureSnapshot.snapshot_date == latest_date)
        return (
            query.order_by(PostureSnapshot.framework, PostureSnapshot.control_id)
            .offset(offset)
            .limit(limit)
            .all()
        )

    def framework_avg_scores_at(self, snapshot_date: Any) -> list[tuple[str, float]]:
        """Average posture score per framework at a specific snapshot date.

        Returns list of (framework, avg_score) tuples.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("framework_avg_scores_at"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.framework_avg_scores_at(snapshot_date)
            finally:
                readers.close()
        return (
            self.session.query(
                PostureSnapshot.framework,
                func.avg(PostureSnapshot.posture_score).label("avg_score"),
            )
            .filter(PostureSnapshot.snapshot_date == snapshot_date)
            .group_by(PostureSnapshot.framework)
            .all()
        )

    def effectiveness_latest(
        self,
        *,
        framework: str | None = None,
        days: int = 365,
    ) -> list[PostureSnapshot]:
        """Latest effectiveness snapshot per (framework, control_id).

        Uses a subquery to get the max snapshot_date per (framework, control_id)
        where uptime_pct is not null, within the given day window.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        latest_sub = (
            self.session.query(
                PostureSnapshot.framework,
                PostureSnapshot.control_id,
                func.max(PostureSnapshot.snapshot_date).label("max_date"),
            )
            .filter(
                PostureSnapshot.snapshot_date >= cutoff,
                PostureSnapshot.uptime_pct.isnot(None),
            )
            .group_by(PostureSnapshot.framework, PostureSnapshot.control_id)
        )
        if framework:
            latest_sub = latest_sub.filter(PostureSnapshot.framework == framework)
        latest_sub = latest_sub.subquery()

        return (
            self.session.query(PostureSnapshot)
            .join(
                latest_sub,
                (PostureSnapshot.framework == latest_sub.c.framework)
                & (PostureSnapshot.control_id == latest_sub.c.control_id)
                & (PostureSnapshot.snapshot_date == latest_sub.c.max_date),
            )
            .all()
        )


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

    def list_filtered(
        self,
        *,
        role: str | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[User]:
        """Filtered user list with optional role/active filters."""
        query = self.session.query(User)
        if role:
            query = query.filter(User.role == role)
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        return query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()

    def deactivate_api_keys(self, user_id: str) -> None:
        """Deactivate all active API keys for a user."""
        self.session.query(APIKey).filter(
            APIKey.user_id == user_id, APIKey.is_active == True  # noqa: E712
        ).update({"is_active": False}, synchronize_session="fetch")


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
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("latest_per_connector"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.latest_per_connector()
            finally:
                readers.close()
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

    def latest_started_at(self) -> datetime | None:
        """Timestamp of the most recent connector run start."""
        return self.session.query(func.max(ConnectorRun.started_at)).scalar()

    def latest_per_provider(self) -> list[ConnectorRun]:
        """Most recent run per provider (ignoring source_type).

        Used by dashboard to show connector health per provider.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("latest_per_provider"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.latest_per_provider()
            finally:
                readers.close()
        subq = (
            self.session.query(
                ConnectorRun.provider,
                func.max(ConnectorRun.started_at).label("latest_started"),
            )
            .group_by(ConnectorRun.provider)
            .subquery()
        )
        return (
            self.session.query(ConnectorRun)
            .join(
                subq,
                (ConnectorRun.provider == subq.c.provider)
                & (ConnectorRun.started_at == subq.c.latest_started),
            )
            .all()
        )

    def latest_by_provider(self, provider: str) -> ConnectorRun | None:
        """Most recent run for a specific provider."""
        return (
            self.session.query(ConnectorRun)
            .filter(ConnectorRun.provider == provider)
            .order_by(ConnectorRun.started_at.desc())
            .first()
        )

    def find_running(self) -> ConnectorRun | None:
        """Return a currently-running connector run, or None."""
        return (
            self.session.query(ConnectorRun)
            .filter(ConnectorRun.status == "running")
            .first()
        )

    def is_running(self) -> bool:
        """Check if any pipeline run is currently in progress."""
        return (
            self.session.query(ConnectorRun)
            .filter(ConnectorRun.status == "running")
            .count()
            > 0
        )

    def latest_run(self) -> ConnectorRun | None:
        """Most recent connector run by started_at."""
        return (
            self.session.query(ConnectorRun)
            .order_by(ConnectorRun.started_at.desc())
            .first()
        )

    def total_event_count(self) -> int:
        """Sum of event_count across all connector runs."""
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("total_event_count"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.total_event_count()
            finally:
                readers.close()
        return int(self.session.query(func.sum(ConnectorRun.event_count)).scalar() or 0)


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

    def open_issues_by_priority(self) -> list[tuple[str, int]]:
        """Count of open issues grouped by priority.

        Returns list of (priority, count) tuples.
        Excludes issues with status 'closed' or 'verified'.
        """
        return (
            self.session.query(Issue.priority, func.count(Issue.id).label("cnt"))
            .filter(Issue.status.notin_(["closed", "verified"]))
            .group_by(Issue.priority)
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

    def list_filtered(
        self,
        *,
        department: str | None = None,
        hr_status: str | None = None,
        has_flags: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Personnel], int]:
        """Filtered active personnel list with total count. Returns (rows, total)."""
        query = self.session.query(Personnel).filter(Personnel.is_active == True)  # noqa: E712
        if department:
            query = query.filter(Personnel.department == department)
        if hr_status:
            query = query.filter(Personnel.hr_status == hr_status)
        if has_flags is True:
            query = query.filter(Personnel.risk_score > 0)
        elif has_flags is False:
            query = query.filter(Personnel.risk_score == 0)
        total = query.count()
        rows = query.order_by(Personnel.full_name).offset(offset).limit(limit).all()
        return rows, total


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

    def list_filtered(
        self,
        *,
        vendor_name: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Questionnaire], int]:
        """Filtered questionnaire list with total count. Returns (rows, total)."""
        query = self.session.query(Questionnaire)
        if vendor_name:
            query = query.filter(Questionnaire.vendor_name == vendor_name)
        if status:
            query = query.filter(Questionnaire.status == status)
        total = query.count()
        rows = query.order_by(Questionnaire.created_at.desc()).offset(offset).limit(limit).all()
        return rows, total


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

    def list_filtered(
        self,
        *,
        scope_filter: Any = None,
        silo_type: str | None = None,
        classification: str | None = None,
        provider: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[DataSilo], int]:
        """Filtered active data silo list with total count. Returns (rows, total).

        ``scope_filter`` is an optional callable ``(query, model) -> query``
        for ABAC scope restrictions.
        """
        query = self.session.query(DataSilo).filter(DataSilo.is_active == True)  # noqa: E712
        if scope_filter is not None:
            query = scope_filter(query, DataSilo)
        if silo_type:
            query = query.filter(DataSilo.silo_type == silo_type)
        if classification:
            query = query.filter(DataSilo.data_classification == classification)
        if provider:
            query = query.filter(DataSilo.provider == provider)
        total = query.count()
        rows = query.order_by(DataSilo.name).offset(offset).limit(limit).all()
        return rows, total


# ---------------------------------------------------------------------------
# Control Mapping Repository
# ---------------------------------------------------------------------------


class ControlMappingRepository(BaseRepository):
    """Control mapping queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, ControlMapping)

    def list_frameworks(
        self,
        *,
        scope_filter: Any = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[tuple[str, int]]:
        """Distinct frameworks with control counts.

        Returns list of (framework_name, control_count) tuples.
        ``scope_filter`` is an optional callable ``(query, model) -> query``.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("list_frameworks"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.list_frameworks(limit, offset)
            finally:
                readers.close()
        query = self.session.query(ControlMapping)
        if scope_filter is not None:
            query = scope_filter(query, ControlMapping)
        return (
            query.with_entities(
                ControlMapping.framework,
                func.count(func.distinct(ControlMapping.control_id)),
            )
            .group_by(ControlMapping.framework)
            .offset(offset)
            .limit(limit)
            .all()
        )

    def list_controls(
        self,
        framework_id: str,
        *,
        scope_filter: Any = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[tuple[str, str, str | None, int]]:
        """Controls within a framework with result counts.

        Returns list of (framework, control_id, control_family, result_count) tuples.
        ``scope_filter`` is an optional callable ``(query, model) -> query``.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if settings.lake_reads_enabled("list_controls"):
            from warlock.lake.readers import LakeReaders

            readers = LakeReaders(settings.lake_path)
            try:
                return readers.list_controls(framework_id, limit, offset)
            finally:
                readers.close()
        query = self.session.query(ControlMapping)
        if scope_filter is not None:
            query = scope_filter(query, ControlMapping)
        return (
            query.with_entities(
                ControlMapping.framework,
                ControlMapping.control_id,
                ControlMapping.control_family,
                func.count(ControlResult.id),
            )
            .outerjoin(ControlResult, ControlResult.control_mapping_id == ControlMapping.id)
            .filter(ControlMapping.framework == framework_id)
            .group_by(
                ControlMapping.framework,
                ControlMapping.control_id,
                ControlMapping.control_family,
            )
            .offset(offset)
            .limit(limit)
            .all()
        )


# ---------------------------------------------------------------------------
# Compliance Drift Repository
# ---------------------------------------------------------------------------


class ComplianceDriftRepository(BaseRepository):
    """Compliance drift queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, ComplianceDrift)

    def recent(self, limit: int = 5) -> list[ComplianceDrift]:
        """Most recent drift events."""
        return (
            self.session.query(ComplianceDrift)
            .order_by(ComplianceDrift.detected_at.desc())
            .limit(limit)
            .all()
        )


# ---------------------------------------------------------------------------
# Audit Entry Repository
# ---------------------------------------------------------------------------


class AuditEntryRepository(BaseRepository):
    """Audit trail queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, AuditEntry)

    def list_filtered(
        self,
        *,
        action: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        actor: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        escape_like_fn: Any = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        """Filtered audit trail with total count. Returns (rows, total).

        ``escape_like_fn`` escapes LIKE wildcards for the actor search.
        """
        query = self.session.query(AuditEntry)
        if action:
            query = query.filter(AuditEntry.action == action)
        if entity_type:
            query = query.filter(AuditEntry.entity_type == entity_type)
        if entity_id:
            query = query.filter(AuditEntry.entity_id == entity_id)
        if actor:
            escaped = escape_like_fn(actor) if escape_like_fn else actor
            query = query.filter(AuditEntry.actor.ilike(f"%{escaped}%"))
        if date_from:
            query = query.filter(AuditEntry.created_at >= date_from)
        if date_to:
            query = query.filter(AuditEntry.created_at <= date_to)
        total = query.count()
        rows = query.order_by(AuditEntry.sequence.desc()).offset(offset).limit(limit).all()
        return rows, total

    def total_count(self) -> int:
        """Total number of audit entries."""
        return self.session.query(func.count(AuditEntry.id)).scalar() or 0


# ---------------------------------------------------------------------------
# Legal Hold Repository
# ---------------------------------------------------------------------------


class LegalHoldRepository(BaseRepository):
    """Legal hold queries."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, LegalHold)


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
        self.control_mappings = ControlMappingRepository(session)
        self.compliance_drift = ComplianceDriftRepository(session)
        self.audit_entries = AuditEntryRepository(session)
        self.legal_holds = LegalHoldRepository(session)


def get_repos(session: Session) -> Repositories:
    """Create a Repositories bundle for the given session."""
    return Repositories(session)
