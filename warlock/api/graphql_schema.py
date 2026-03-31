"""GraphQL API schema for Warlock GRC platform.

Provides a Strawberry GraphQL schema exposing findings, control results,
issues, POAMs, vendors, system profiles, and risk analyses. The strawberry
dependency is optional -- when not installed, ``get_graphql_app()`` returns
``None`` so the caller can skip mounting.

Usage::

    app = get_graphql_app()
    if app is not None:
        fastapi_app.include_router(app, prefix="/graphql")
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import -- strawberry-graphql is an optional dependency
# ---------------------------------------------------------------------------

try:
    import strawberry
    from strawberry.fastapi import GraphQLRouter

    _HAS_STRAWBERRY = True
except ImportError:  # pragma: no cover
    _HAS_STRAWBERRY = False
    strawberry = None  # type: ignore[assignment]
    GraphQLRouter = None  # type: ignore[assignment,misc]


def _build_schema():
    """Build and return the Strawberry schema.  Only called when strawberry is installed."""

    from datetime import datetime

    import strawberry as sb

    # ------------------------------------------------------------------
    # Types
    # ------------------------------------------------------------------

    @sb.type
    class FindingType:
        id: str
        title: str
        observation_type: str
        severity: str
        source: str
        provider: str
        resource_type: Optional[str]
        resource_id: Optional[str]
        confidence: Optional[float]
        observed_at: Optional[datetime]
        ingested_at: Optional[datetime]

    @sb.type
    class ControlResultType:
        id: str
        framework: str
        control_id: str
        status: str
        severity: str
        assertion_name: Optional[str]
        assertion_passed: Optional[bool]
        ai_confidence: Optional[float]
        remediation_summary: Optional[str]
        assessed_at: Optional[datetime]
        assessor: str

    @sb.type
    class IssueType:
        id: str
        title: str
        description: Optional[str]
        status: str
        priority: str
        framework: Optional[str]
        control_id: Optional[str]
        assigned_to: Optional[str]
        due_date: Optional[datetime]
        created_at: Optional[datetime]

    @sb.type
    class POAMType:
        id: str
        framework: str
        control_id: str
        weakness_description: str
        severity: str
        status: str
        risk_level: Optional[str]
        scheduled_completion: Optional[datetime]
        actual_completion: Optional[datetime]
        delay_count: Optional[int]
        created_at: Optional[datetime]

    @sb.type
    class VendorType:
        id: str
        name: str
        tier: Optional[str]
        risk_score: Optional[float]
        contract_expires: Optional[datetime]
        last_assessment: Optional[datetime]
        blast_radius_score: Optional[float]
        dependent_control_count: Optional[int]

    @sb.type
    class SystemType:
        id: str
        name: str
        acronym: Optional[str]
        description: Optional[str]
        overall_impact: Optional[str]
        authorization_status: Optional[str]
        deployment_model: Optional[str]
        service_model: Optional[str]
        is_active: Optional[bool]

    @sb.type
    class RiskType:
        framework: str
        scenario_count: int
        mean_ale: float
        max_var_95: float
        max_var_99: float
        avg_control_effectiveness: Optional[float]

    # ------------------------------------------------------------------
    # Helpers: row -> GraphQL type converters
    # ------------------------------------------------------------------

    def _finding_from_row(row) -> FindingType:
        from warlock.utils import ensure_aware

        return FindingType(
            id=row.id,
            title=row.title,
            observation_type=row.observation_type,
            severity=row.severity,
            source=row.source,
            provider=row.provider,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            confidence=row.confidence,
            observed_at=ensure_aware(row.observed_at) if row.observed_at else None,
            ingested_at=ensure_aware(row.ingested_at) if row.ingested_at else None,
        )

    def _control_result_from_row(row) -> ControlResultType:
        from warlock.utils import ensure_aware

        return ControlResultType(
            id=row.id,
            framework=row.framework,
            control_id=row.control_id,
            status=row.status,
            severity=row.severity,
            assertion_name=row.assertion_name,
            assertion_passed=row.assertion_passed,
            ai_confidence=row.ai_confidence,
            remediation_summary=row.remediation_summary,
            assessed_at=ensure_aware(row.assessed_at) if row.assessed_at else None,
            assessor=row.assessor,
        )

    def _issue_from_row(row) -> IssueType:
        from warlock.utils import ensure_aware

        return IssueType(
            id=row.id,
            title=row.title,
            description=row.description,
            status=row.status,
            priority=row.priority,
            framework=row.framework,
            control_id=row.control_id,
            assigned_to=row.assigned_to,
            due_date=ensure_aware(row.due_date) if row.due_date else None,
            created_at=ensure_aware(row.created_at) if row.created_at else None,
        )

    def _poam_from_row(row) -> POAMType:
        from warlock.utils import ensure_aware

        return POAMType(
            id=row.id,
            framework=row.framework,
            control_id=row.control_id,
            weakness_description=row.weakness_description,
            severity=row.severity,
            status=row.status,
            risk_level=row.risk_level,
            scheduled_completion=(
                ensure_aware(row.scheduled_completion) if row.scheduled_completion else None
            ),
            actual_completion=(
                ensure_aware(row.actual_completion) if row.actual_completion else None
            ),
            delay_count=row.delay_count,
            created_at=ensure_aware(row.created_at) if row.created_at else None,
        )

    def _vendor_from_row(row) -> VendorType:
        return VendorType(
            id=row.id,
            name=row.name,
            tier=row.tier,
            risk_score=row.risk_score,
            contract_expires=row.contract_expires,
            last_assessment=row.last_assessment,
            blast_radius_score=row.blast_radius_score,
            dependent_control_count=row.dependent_control_count,
        )

    def _system_from_row(row) -> SystemType:
        return SystemType(
            id=row.id,
            name=row.name,
            acronym=row.acronym,
            description=row.description,
            overall_impact=row.overall_impact,
            authorization_status=row.authorization_status,
            deployment_model=row.deployment_model,
            service_model=row.service_model,
            is_active=row.is_active,
        )

    # ------------------------------------------------------------------
    # Query root
    # ------------------------------------------------------------------

    @sb.type
    class Query:
        @sb.field
        def findings(
            self,
            framework: Optional[str] = None,
            severity: Optional[str] = None,
            limit: int = 50,
        ) -> list[FindingType]:
            """Return findings, optionally filtered by framework or severity."""
            from warlock.db.engine import get_session
            from warlock.db.models import ControlMapping, Finding

            limit = min(max(limit, 1), 1000)
            with get_session() as session:
                q = session.query(Finding)
                if framework:
                    subq = (
                        session.query(ControlMapping.finding_id)
                        .filter(ControlMapping.framework == framework)
                        .distinct()
                        .subquery()
                    )
                    q = q.filter(Finding.id.in_(session.query(subq)))
                if severity:
                    q = q.filter(Finding.severity == severity.lower())
                rows = q.order_by(Finding.ingested_at.desc()).limit(limit).all()
                return [_finding_from_row(r) for r in rows]

        @sb.field
        def control_results(
            self,
            framework: Optional[str] = None,
            status: Optional[str] = None,
            limit: int = 50,
        ) -> list[ControlResultType]:
            """Return control results, optionally filtered by framework or status."""
            from warlock.db.engine import get_session
            from warlock.db.models import ControlResult

            limit = min(max(limit, 1), 1000)
            with get_session() as session:
                q = session.query(ControlResult)
                if framework:
                    q = q.filter(ControlResult.framework == framework)
                if status:
                    q = q.filter(ControlResult.status == status.lower())
                rows = q.order_by(ControlResult.assessed_at.desc()).limit(limit).all()
                return [_control_result_from_row(r) for r in rows]

        @sb.field
        def issues(
            self,
            status: Optional[str] = None,
            priority: Optional[str] = None,
            limit: int = 50,
        ) -> list[IssueType]:
            """Return issues, optionally filtered by status or priority."""
            from warlock.db.engine import get_session
            from warlock.db.models import Issue

            limit = min(max(limit, 1), 1000)
            with get_session() as session:
                q = session.query(Issue)
                if status:
                    q = q.filter(Issue.status == status.lower())
                if priority:
                    q = q.filter(Issue.priority == priority.lower())
                rows = q.order_by(Issue.created_at.desc()).limit(limit).all()
                return [_issue_from_row(r) for r in rows]

        @sb.field
        def poams(
            self,
            framework: Optional[str] = None,
            status: Optional[str] = None,
            limit: int = 50,
        ) -> list[POAMType]:
            """Return POAMs, optionally filtered by framework or status."""
            from warlock.db.engine import get_session
            from warlock.db.models import POAM

            limit = min(max(limit, 1), 1000)
            with get_session() as session:
                q = session.query(POAM)
                if framework:
                    q = q.filter(POAM.framework == framework)
                if status:
                    q = q.filter(POAM.status == status.lower())
                rows = q.order_by(POAM.created_at.desc()).limit(limit).all()
                return [_poam_from_row(r) for r in rows]

        @sb.field
        def vendors(self, limit: int = 50) -> list[VendorType]:
            """Return all vendors."""
            from warlock.db.engine import get_session
            from warlock.db.models import Vendor

            limit = min(max(limit, 1), 1000)
            with get_session() as session:
                rows = session.query(Vendor).order_by(Vendor.name).limit(limit).all()
                return [_vendor_from_row(r) for r in rows]

        @sb.field
        def compliance_score(self, framework: Optional[str] = None) -> float:
            """Return the compliance score (0-100) for a framework or overall.

            Calculated as: (compliant results / total assessed results) * 100.
            Excludes ``not_assessed`` and ``not_applicable`` statuses from the
            denominator so the score reflects only actively evaluated controls.
            """
            from warlock.db.engine import get_session
            from warlock.db.models import ControlResult

            excluded = {"not_assessed", "not_applicable"}
            with get_session() as session:
                q = session.query(ControlResult).filter(ControlResult.status.notin_(excluded))
                if framework:
                    q = q.filter(ControlResult.framework == framework)

                total = q.count()
                if total == 0:
                    return 0.0

                compliant = q.filter(
                    ControlResult.status.in_(["compliant", "inherited_compliant", "risk_accepted"])
                ).count()
                return round((compliant / total) * 100, 2)

        @sb.field
        def risk_summary(self, framework: Optional[str] = None) -> Optional[RiskType]:
            """Return aggregated risk metrics for a framework or overall."""
            from warlock.db.engine import get_session
            from warlock.db.models import RiskAnalysis

            with get_session() as session:
                q = session.query(RiskAnalysis)
                if framework:
                    q = q.filter(RiskAnalysis.framework == framework)

                rows = q.all()
                if not rows:
                    return None

                fw = framework or "all"
                mean_ales = [r.mean_ale for r in rows]
                var_95s = [r.var_95 for r in rows]
                var_99s = [r.var_99 for r in rows]
                effs = [
                    r.control_effectiveness for r in rows if r.control_effectiveness is not None
                ]

                return RiskType(
                    framework=fw,
                    scenario_count=len(rows),
                    mean_ale=round(sum(mean_ales) / len(mean_ales), 2),
                    max_var_95=round(max(var_95s), 2),
                    max_var_99=round(max(var_99s), 2),
                    avg_control_effectiveness=(round(sum(effs) / len(effs), 2) if effs else None),
                )

    return sb.Schema(query=Query)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_graphql_app() -> "GraphQLRouter | None":
    """Return a Strawberry FastAPI GraphQL router, or None if strawberry is not installed."""
    if not _HAS_STRAWBERRY:
        logger.info("strawberry-graphql not installed -- GraphQL endpoint disabled")
        return None

    schema = _build_schema()
    return GraphQLRouter(schema, path="/graphql")
