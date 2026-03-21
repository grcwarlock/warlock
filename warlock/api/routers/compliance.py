"""Compliance routes: frameworks, controls, findings, results, connectors, dashboard."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission, apply_framework_scope, apply_source_scope
from warlock.api.routers.schemas import PaginatedResponse, _dt_str, _escape_like, _parse_dt
from warlock.db.models import User
from warlock.db.repository import get_repos

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TTL caches (backed by shared cache for multi-worker compatibility)
# ---------------------------------------------------------------------------
_COVERAGE_CACHE_TTL = 300  # seconds
_DASHBOARD_CACHE_TTL = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FrameworkResponse(BaseModel):
    name: str
    control_count: int


class ControlResponse(BaseModel):
    framework: str
    control_id: str
    control_family: str | None
    result_count: int


class FindingResponse(BaseModel):
    id: str
    title: str
    observation_type: str
    severity: str
    resource_id: str | None
    resource_type: str | None
    source: str
    provider: str
    observed_at: str
    detail: Any | None = None

    model_config = {"from_attributes": True}


class ControlResultResponse(BaseModel):
    id: str
    framework: str
    control_id: str
    status: str
    severity: str
    assessor: str
    assertion_name: str | None
    assertion_passed: bool | None
    assessed_at: str
    finding_id: str
    remediation_summary: str | None = None

    model_config = {"from_attributes": True}


class CoverageResponse(BaseModel):
    framework: str
    total: int
    compliant: int
    non_compliant: int
    partial: int
    not_assessed: int
    rate: float


class PostureResponse(BaseModel):
    framework: str
    control_id: str
    status: str
    posture_score: float
    sufficiency_score: float
    evidence_sources: list[str]
    evidence_freshness: float | None

    model_config = {"from_attributes": True}


class ControlDetailResource(BaseModel):
    resource_id: str
    resource_type: str
    source: str
    provider: str | None = None
    region: str | None = None
    severity: str | None = None


class ControlDetailRemediation(BaseModel):
    summary: str | None = None
    steps: list[str] = []
    console_path: str | None = None
    recommended_reading: list[str] = []


class ControlDetailResponse(BaseModel):
    control_id: str
    frameworks: list[str]
    description: str | None = None
    total_results: int
    compliant_count: int
    non_compliant_count: int
    partial_count: int
    not_assessed_count: int
    passing_resources: list[ControlDetailResource]
    failing_resources: list[ControlDetailResource]
    remediation: ControlDetailRemediation | None = None
    ai_remediation: dict | None = None  # per-resource AI commands, only when ai=true


class ConnectorResponse(BaseModel):
    provider: str
    source_type: str
    enabled: bool
    last_run: str | None
    last_status: str | None


class CadenceResponse(BaseModel):
    framework: str
    control_id: str
    required_frequency: str
    required_hours: float
    last_evidence_at: str | None
    hours_since: float | None
    is_stale: bool
    staleness_ratio: float


class SufficiencyResponse(BaseModel):
    framework: str
    control_id: str
    score: float
    evidence_volume: float
    evidence_freshness: float
    evidence_diversity: float
    assertion_coverage: float
    gaps: list[str]


class PostureHistoryPointResponse(BaseModel):
    date: str
    status: str
    posture_score: float
    sufficiency_score: float
    evidence_freshness_hours: float | None


class PostureHistoryResponse(BaseModel):
    framework: str
    control_id: str
    trend: str
    trend_slope: float
    points: list[PostureHistoryPointResponse]


# ---------------------------------------------------------------------------
# Routes — Frameworks & Controls
# ---------------------------------------------------------------------------


@router.get("/frameworks", response_model=list[FrameworkResponse])
def list_frameworks(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    # S-1: Apply ABAC scope filters
    repos = get_repos(db)
    rows = repos.control_mappings.list_frameworks(
        scope_filter=lambda q, m: apply_framework_scope(q, m, current_user),
        limit=limit,
        offset=offset,
    )
    return [FrameworkResponse(name=fw, control_count=cnt) for fw, cnt in rows]


@router.get("/frameworks/{framework_id}/controls", response_model=list[ControlResponse])
def list_controls(
    framework_id: str,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    # S-1: Apply ABAC scope filters
    repos = get_repos(db)
    rows = repos.control_mappings.list_controls(
        framework_id,
        scope_filter=lambda q, m: apply_framework_scope(q, m, current_user),
        limit=limit,
        offset=offset,
    )
    return [
        ControlResponse(framework=fw, control_id=cid, control_family=cf, result_count=cnt)
        for fw, cid, cf, cnt in rows
    ]


# ---------------------------------------------------------------------------
# Routes — Findings
# ---------------------------------------------------------------------------


@router.get("/findings", response_model=PaginatedResponse)
def list_findings(
    framework: str | None = Query(None),
    severity: str | None = Query(None),
    observation_type: str | None = Query(None),
    source: str | None = Query(None),
    provider: str | None = Query(None),
    resource_type: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-1: Apply ABAC scope filters
    repos = get_repos(db)
    rows, total = repos.findings.list_filtered(
        scope_filter=lambda q, m: apply_source_scope(q, m, current_user),
        framework=framework,
        severity=severity,
        observation_type=observation_type,
        source=source,
        provider=provider,
        resource_type=resource_type,
        date_from=_parse_dt(date_from) if date_from else None,
        date_to=_parse_dt(date_to) if date_to else None,
        limit=limit,
        offset=offset,
    )

    items = [
        FindingResponse(
            id=f.id,
            title=f.title,
            observation_type=f.observation_type,
            severity=f.severity,
            resource_id=f.resource_id,
            resource_type=f.resource_type,
            source=f.source,
            provider=f.provider,
            observed_at=_dt_str(f.observed_at) or "",
            detail=f.detail,
        )
        for f in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-1: Apply ABAC scope filters
    repos = get_repos(db)
    f = repos.findings.get_scoped(
        finding_id,
        scope_filter=lambda q, m: apply_source_scope(q, m, current_user),
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse(
        id=f.id,
        title=f.title,
        observation_type=f.observation_type,
        severity=f.severity,
        resource_id=f.resource_id,
        resource_type=f.resource_type,
        source=f.source,
        provider=f.provider,
        observed_at=_dt_str(f.observed_at) or "",
        detail=f.detail,
    )


# ---------------------------------------------------------------------------
# Routes — Control Results
# ---------------------------------------------------------------------------


@router.get("/results", response_model=PaginatedResponse)
def list_results(
    framework: str | None = Query(None),
    control_id: str | None = Query(None),
    result_status: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    assessor: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-1: Apply ABAC scope filters
    repos = get_repos(db)
    rows, total = repos.control_results.list_filtered(
        scope_filter=lambda q, m: apply_framework_scope(q, m, current_user),
        framework=framework,
        control_id=control_id,
        result_status=result_status,
        severity=severity,
        assessor=assessor,
        date_from=_parse_dt(date_from) if date_from else None,
        date_to=_parse_dt(date_to) if date_to else None,
        limit=limit,
        offset=offset,
        escape_like_fn=_escape_like,
    )

    items = [
        ControlResultResponse(
            id=r.id,
            framework=r.framework,
            control_id=r.control_id,
            status=r.status,
            severity=r.severity,
            assessor=r.assessor,
            assertion_name=r.assertion_name,
            assertion_passed=r.assertion_passed,
            assessed_at=_dt_str(r.assessed_at) or "",
            finding_id=r.finding_id,
            remediation_summary=r.remediation_summary,
        )
        for r in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/results/coverage")
def results_coverage(
    framework: str | None = Query(None),
    ai: bool = Query(False, description="Include AI narrative for coverage gaps"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Coverage summary: per-framework counts of each status.

    Results are cached in-process for 300 seconds.  The cache is
    invalidated when a new ConnectorRun is detected (by comparing the
    latest ``ConnectorRun.started_at`` timestamp against the value stored
    when the cache entry was written).
    """
    from warlock.utils.cache import get_cache

    cache_key = f"coverage:{framework}:{current_user.id}"

    repos = get_repos(db)

    # Fetch the latest ConnectorRun timestamp cheaply (single scalar query)
    latest_run: datetime | None = repos.connector_runs.latest_started_at()
    latest_run_str = latest_run.isoformat() if latest_run else ""

    cached = get_cache().get(cache_key)
    if cached is not None:
        if cached.get("latest_run") == latest_run_str:
            log.debug("coverage cache hit (key=%s)", cache_key)
            return cached["data"]

    # --- Cache miss: compute fresh ---
    # S-1: Apply ABAC scope filter before aggregation
    rows = repos.control_results.coverage_by_status(
        scope_filter=lambda q, m: apply_framework_scope(q, m, current_user),
        framework=framework,
    )

    # Aggregate per framework
    fw_stats: dict[str, dict[str, int]] = {}
    for fw, st, cnt in rows:
        if fw not in fw_stats:
            fw_stats[fw] = {
                "compliant": 0,
                "non_compliant": 0,
                "partial": 0,
                "not_assessed": 0,
                "total": 0,
            }
        fw_stats[fw]["total"] += cnt
        if st == "compliant":
            fw_stats[fw]["compliant"] += cnt
        elif st == "non_compliant":
            fw_stats[fw]["non_compliant"] += cnt
        elif st == "partial":
            fw_stats[fw]["partial"] += cnt
        else:
            fw_stats[fw]["not_assessed"] += cnt

    response = [
        CoverageResponse(
            framework=fw,
            total=s["total"],
            compliant=s["compliant"],
            non_compliant=s["non_compliant"],
            partial=s["partial"],
            not_assessed=s["not_assessed"],
            rate=round(s["compliant"] / s["total"] * 100, 2) if s["total"] > 0 else 0.0,
        )
        for fw, s in sorted(fw_stats.items())
    ]

    get_cache().set(
        cache_key, {"data": response, "latest_run": latest_run_str}, ttl=_COVERAGE_CACHE_TTL
    )
    log.debug("coverage cache miss — refreshed (key=%s)", cache_key)

    if ai:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        ai_svc = get_ai_service()
        if ai_svc.is_task_enabled(AITask.EXECUTIVE_REPORT):
            coverage_context = {
                "frameworks": [
                    {
                        "framework": r.framework,
                        "total": r.total,
                        "compliant": r.compliant,
                        "non_compliant": r.non_compliant,
                        "partial": r.partial,
                        "not_assessed": r.not_assessed,
                        "rate": r.rate,
                    }
                    for r in response
                ],
            }
            ai_result = ai_svc.reason(AITask.EXECUTIVE_REPORT, context=coverage_context)
            ai_narrative = ai_result.value if ai_result.ai_used else None
            ai_meta: dict[str, Any] | None = None
            if ai_result.ai_used:
                ai_meta = {
                    "model": ai_result.model,
                    "provider": ai_result.provider,
                    "latency_ms": ai_result.latency_ms,
                    "confidence": ai_result.confidence,
                }
            return {
                "coverage": [r.model_dump() for r in response],
                "ai_narrative": ai_narrative,
                "ai_metadata": ai_meta,
            }

    return response


@router.get("/results/posture", response_model=list[PostureResponse])
def results_posture(
    framework: str | None = Query(None),
    control_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Posture scores from the latest snapshot."""
    repos = get_repos(db)

    # Get the latest snapshot date
    latest_date_subq = repos.posture.latest_snapshot_date()

    # S-1: Apply ABAC scope filters
    rows = repos.posture.list_latest_posture(
        scope_filter=lambda q, m: apply_framework_scope(q, m, current_user),
        framework=framework,
        control_id=control_id,
        latest_date=latest_date_subq,
        limit=limit,
        offset=offset,
    )

    return [
        PostureResponse(
            framework=p.framework,
            control_id=p.control_id,
            status=p.status,
            posture_score=p.posture_score,
            sufficiency_score=p.sufficiency_score,
            evidence_sources=p.evidence_sources or [],
            evidence_freshness=p.evidence_freshness_hours,
        )
        for p in rows
    ]


# ---------------------------------------------------------------------------
# Routes — Control Detail
# ---------------------------------------------------------------------------


@router.get("/controls/{control_id}", response_model=ControlDetailResponse)
def get_control_detail_endpoint(
    control_id: str,
    framework: str | None = Query(None, description="Filter to specific framework"),
    ai: bool = Query(False, description="Include AI-enhanced remediation"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Full control detail: status counts, passing/failing resources, remediation."""
    from warlock.assessors.remediation_loader import (
        get_control_detail,
        get_ai_control_remediation,
    )

    detail = get_control_detail(db, control_id, framework)
    if detail is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No results found for control '{control_id}'",
        )

    # Map status_counts to the response model fields
    sc = detail.get("status_counts", {})
    compliant_count = sc.get("compliant", 0)
    non_compliant_count = sc.get("non_compliant", 0)
    partial_count = sc.get("partial", 0)
    not_assessed_count = (
        detail["total_resources"] - compliant_count - non_compliant_count - partial_count
    )

    # Build resource lists
    passing = [
        ControlDetailResource(
            resource_id=r.get("resource_id", ""),
            resource_type=r.get("resource_type", ""),
            source=r.get("source", ""),
            provider=r.get("provider") if r.get("provider") else None,
            region=r.get("region"),
            severity=r.get("severity"),
        )
        for r in detail.get("passing_resources", [])
    ]
    failing = [
        ControlDetailResource(
            resource_id=r.get("resource_id", ""),
            resource_type=r.get("resource_type", ""),
            source=r.get("source", ""),
            provider=r.get("provider") if r.get("provider") else None,
            region=r.get("region"),
            severity=r.get("severity"),
        )
        for r in detail.get("failing_resources", [])
    ]

    # Build remediation model from KB dict
    remediation = None
    kb = detail.get("remediation")
    if kb:
        remediation = ControlDetailRemediation(
            summary=kb.get("summary"),
            steps=kb.get("remediation_steps", kb.get("steps", [])),
            console_path=kb.get("console_path"),
            recommended_reading=kb.get("recommended_reading", []),
        )

    # AI-enhanced remediation (only when requested)
    ai_remediation = None
    if ai and failing:
        try:
            fw = framework or (detail["frameworks"][0] if detail["frameworks"] else "unknown")
            ai_remediation = get_ai_control_remediation(
                control_id=control_id,
                framework=fw,
                failing_resources=detail.get("failing_resources", []),
                remediation=kb,
            )
        except Exception:
            log.warning("AI remediation failed for %s", control_id, exc_info=True)

    return ControlDetailResponse(
        control_id=detail["control_id"],
        frameworks=detail["frameworks"],
        description=detail.get("description"),
        total_results=detail["total_resources"],
        compliant_count=compliant_count,
        non_compliant_count=non_compliant_count,
        partial_count=partial_count,
        not_assessed_count=not_assessed_count,
        passing_resources=passing,
        failing_resources=failing,
        remediation=remediation,
        ai_remediation=ai_remediation,
    )


# ---------------------------------------------------------------------------
# Routes — Cadence & Sufficiency
# ---------------------------------------------------------------------------


@router.get("/cadence", response_model=list[CadenceResponse])
def get_cadence(
    framework: str | None = Query(None),
    stale_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Check monitoring cadence — are controls being assessed on schedule?"""
    from warlock.assessors.cadence import CadenceChecker

    checker = CadenceChecker()

    if stale_only:
        cadences = checker.get_stale_controls(db, framework=framework)
    elif framework:
        cadences = checker.check_framework(db, framework)
    else:
        all_c = checker.check_all(db)
        cadences = [c for clist in all_c.values() for c in clist]

    return [
        CadenceResponse(
            framework=c.framework,
            control_id=c.control_id,
            required_frequency=c.required_frequency,
            required_hours=c.required_hours,
            last_evidence_at=c.last_evidence_at.isoformat() if c.last_evidence_at else None,
            hours_since=c.hours_since,
            is_stale=c.is_stale,
            staleness_ratio=c.staleness_ratio,
        )
        for c in cadences
    ]


@router.get("/posture/history", response_model=list[PostureHistoryResponse])
def posture_history(
    framework: str = Query(...),
    control_id: str | None = Query(None),
    days: int = Query(90, ge=1, le=730),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Posture time-series with trend analysis."""
    from warlock.assessors.posture import PostureTimeSeriesQuery

    tsq = PostureTimeSeriesQuery()

    if control_id:
        series_list = [tsq.query_control(db, framework, control_id, days)]
    else:
        series_list = tsq.query_framework(db, framework, days)

    return [
        PostureHistoryResponse(
            framework=ts.framework,
            control_id=ts.control_id,
            trend=ts.trend,
            trend_slope=ts.trend_slope,
            points=[
                PostureHistoryPointResponse(
                    date=p.date.isoformat() if p.date else "",
                    status=p.status,
                    posture_score=p.posture_score,
                    sufficiency_score=p.sufficiency_score,
                    evidence_freshness_hours=p.evidence_freshness_hours,
                )
                for p in ts.points
            ],
        )
        for ts in series_list
    ]


@router.get("/sufficiency", response_model=list[SufficiencyResponse])
def get_sufficiency(
    framework: str | None = Query(None),
    below: float | None = Query(None, description="Only controls below this score"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Evidence sufficiency scores per control."""
    from warlock.assessors.posture import EvidenceSufficiencyScorer

    repos = get_repos(db)
    scorer = EvidenceSufficiencyScorer()

    if framework:
        fw_result = scorer.score_framework(db, framework)
        scores = fw_result.control_scores
    else:
        fw_names = repos.control_results.distinct_frameworks()
        scores = []
        for fw in fw_names:
            fw_result = scorer.score_framework(db, fw)
            scores.extend(fw_result.control_scores)

    if below is not None:
        scores = [s for s in scores if s.score < below]

    scores.sort(key=lambda s: s.score)

    return [
        SufficiencyResponse(
            framework=s.framework,
            control_id=s.control_id,
            score=s.score,
            evidence_volume=s.evidence_volume,
            evidence_freshness=s.evidence_freshness,
            evidence_diversity=s.evidence_diversity,
            assertion_coverage=s.assertion_coverage,
            gaps=s.gaps,
        )
        for s in scores
    ]


# ---------------------------------------------------------------------------
# Routes — Connectors
# ---------------------------------------------------------------------------


@router.get("/connectors", response_model=list[ConnectorResponse])
def list_connectors(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List connectors with their last run status."""
    repos = get_repos(db)
    rows = repos.connector_runs.latest_per_connector()

    # Also include registered connectors that may not have runs yet
    try:
        from warlock.connectors.base import registry

        registered = set(registry.list_types())
    except Exception:
        registered = set()

    seen_providers = set()
    results: list[ConnectorResponse] = []
    for r in rows:
        seen_providers.add(r.provider)
        results.append(
            ConnectorResponse(
                provider=r.provider,
                source_type=r.source_type,
                enabled=True,
                last_run=_dt_str(r.started_at),
                last_status=r.status,
            )
        )

    for provider in sorted(registered - seen_providers):
        results.append(
            ConnectorResponse(
                provider=provider,
                source_type="unknown",
                enabled=True,
                last_run=None,
                last_status=None,
            )
        )

    return results


@router.get("/connectors/{provider}/status", response_model=ConnectorResponse)
def connector_status(
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    last_run = repos.connector_runs.latest_by_provider(provider)

    if not last_run:
        # Check if the connector is at least registered
        try:
            from warlock.connectors.base import registry

            if provider in registry.list_types():
                return ConnectorResponse(
                    provider=provider,
                    source_type="unknown",
                    enabled=True,
                    last_run=None,
                    last_status=None,
                )
        except Exception:
            pass
        raise HTTPException(status_code=404, detail=f"Connector not found: {provider}")

    return ConnectorResponse(
        provider=last_run.provider,
        source_type=last_run.source_type,
        enabled=True,
        last_run=_dt_str(last_run.started_at),
        last_status=last_run.status,
    )


# ---------------------------------------------------------------------------
# Routes — Drift
# ---------------------------------------------------------------------------


@router.get("/drift")
def get_drift(
    framework: str | None = Query(None),
    days: int = Query(30),
    direction: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Get compliance drift events."""
    from warlock.assessors.drift import DriftDetector

    detector = DriftDetector()
    drifts = detector.get_drifts(db, framework=framework, days=days, direction=direction)
    return [
        {
            "id": d.id,
            "framework": d.framework,
            "control_id": d.control_id,
            "drift_direction": d.drift_direction,
            "previous_status": d.previous_status,
            "new_status": d.new_status,
            "correlated_changes": len(d.correlated_change_event_ids or []),
            "detected_at": d.detected_at.isoformat() if d.detected_at else None,
        }
        for d in drifts
    ]


# ---------------------------------------------------------------------------
# Routes — Effectiveness
# ---------------------------------------------------------------------------


@router.get("/effectiveness")
def get_effectiveness(
    framework: str | None = Query(None),
    days: int = Query(365),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Control effectiveness scores over time.

    #22 fix: Use a subquery to get the latest snapshot per (framework, control_id)
    instead of loading all rows and deduplicating in Python.
    """
    repos = get_repos(db)
    rows = repos.posture.effectiveness_latest(framework=framework, days=days)

    return [
        {
            "framework": s.framework,
            "control_id": s.control_id,
            "uptime_pct": s.uptime_pct,
            "mttr_hours": s.mttr_hours,
            "drift_count": s.drift_count,
        }
        for s in rows
    ]


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------


@router.get("/dashboard/summary")
def dashboard_summary(
    ai: bool = Query(False, description="Include AI executive summary narrative"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Real-time compliance dashboard — single call for the frontend.

    Returns:
    - frameworks:       per-framework compliance rate, control counts, trend
    - top_risks:        top 5 non-compliant controls by severity
    - recent_drift:     last 5 compliance drift events
    - open_issues:      count by priority (critical/high/medium/low)
    - posture_score:    overall weighted compliance percentage
    - connectors:       health status of most recent run per provider
    - last_assessment:  timestamp of most recent pipeline completion

    Cached per user for 5 minutes (TTL = 300 s).
    """
    from warlock.utils.cache import get_cache

    cache_key = f"dashboard:{current_user.id}"
    cached = get_cache().get(cache_key)
    if cached is not None:
        return cached

    repos = get_repos(db)

    # -----------------------------------------------------------------
    # frameworks: per-framework compliance rate, control counts, trend
    # -----------------------------------------------------------------
    fw_rows = repos.control_results.dashboard_framework_summary()

    fw_agg: dict[str, dict] = {}
    for framework_val, status_val, cnt in fw_rows:
        if framework_val not in fw_agg:
            fw_agg[framework_val] = {"total": 0, "compliant": 0, "non_compliant": 0}
        fw_agg[framework_val]["total"] += cnt
        if status_val == "compliant":
            fw_agg[framework_val]["compliant"] += cnt
        elif status_val == "non_compliant":
            fw_agg[framework_val]["non_compliant"] += cnt

    # Trend: compare current rate against most-recent posture snapshot rate
    snapshot_rates: dict[str, float] = {}
    latest_snapshot_date = repos.posture.latest_snapshot_date()
    if latest_snapshot_date:
        snap_rows = repos.posture.framework_avg_scores_at(latest_snapshot_date)
        for fw_name, avg_score in snap_rows:
            snapshot_rates[fw_name] = float(avg_score or 0)

    frameworks_out = []
    total_compliant = 0
    total_controls = 0

    for fw, agg in sorted(fw_agg.items()):
        total = agg["total"]
        compliant = agg["compliant"]
        rate = round(compliant / total * 100, 1) if total else 0.0

        total_compliant += compliant
        total_controls += total

        # Trend relative to snapshot
        snap_rate = snapshot_rates.get(fw)
        if snap_rate is None:
            trend = "stable"
        elif rate > snap_rate + 2:
            trend = "improving"
        elif rate < snap_rate - 2:
            trend = "degrading"
        else:
            trend = "stable"

        frameworks_out.append(
            {
                "framework": fw,
                "compliance_rate": rate,
                "total_controls": total,
                "compliant_controls": compliant,
                "non_compliant_controls": agg["non_compliant"],
                "trend": trend,
            }
        )

    # -----------------------------------------------------------------
    # posture_score: overall weighted compliance percentage
    # -----------------------------------------------------------------
    posture_score = round(total_compliant / total_controls * 100, 1) if total_controls else 0.0

    # -----------------------------------------------------------------
    # top_risks: top 5 non-compliant controls by severity
    # -----------------------------------------------------------------
    _severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    top_risk_rows = repos.control_results.top_non_compliant_risks()

    top_risk_sorted = sorted(
        top_risk_rows,
        key=lambda r: (_severity_order.get(r.severity or "info", 99), -(r.cnt or 0)),
    )[:5]

    top_risks = [
        {
            "framework": r.framework,
            "control_id": r.control_id,
            "severity": r.severity,
            "non_compliant_count": r.cnt,
        }
        for r in top_risk_sorted
    ]

    # -----------------------------------------------------------------
    # recent_drift: last 5 compliance drift events
    # -----------------------------------------------------------------
    drift_rows = repos.compliance_drift.recent(limit=5)

    recent_drift = []
    for d in drift_rows:
        dt = d.detected_at
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        recent_drift.append(
            {
                "framework": d.framework,
                "control_id": d.control_id,
                "previous_status": d.previous_status,
                "new_status": d.new_status,
                "drift_direction": d.drift_direction,
                "detected_at": dt.isoformat() if dt else None,
            }
        )

    # -----------------------------------------------------------------
    # open_issues: count by priority
    # -----------------------------------------------------------------
    issue_rows = repos.issues.open_issues_by_priority()
    open_issues: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for priority, cnt in issue_rows:
        if priority in open_issues:
            open_issues[priority] = cnt

    # -----------------------------------------------------------------
    # connectors: health of most recent run per provider
    # -----------------------------------------------------------------
    connector_runs = repos.connector_runs.latest_per_provider()

    connectors = []
    for run in connector_runs:
        started = run.started_at
        if started and started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        completed = run.completed_at
        if completed and completed.tzinfo is None:
            completed = completed.replace(tzinfo=timezone.utc)
        connectors.append(
            {
                "provider": run.provider,
                "source_type": run.source_type,
                "status": run.status,
                "event_count": run.event_count,
                "error_count": run.error_count,
                "started_at": started.isoformat() if started else None,
                "completed_at": completed.isoformat() if completed else None,
            }
        )

    # -----------------------------------------------------------------
    # last_assessment: most recent pipeline completion
    # -----------------------------------------------------------------
    last_assessed = repos.control_results.last_assessed_at()
    last_assessment = None
    if last_assessed:
        if last_assessed.tzinfo is None:
            last_assessed = last_assessed.replace(tzinfo=timezone.utc)
        last_assessment = last_assessed.isoformat()

    # -----------------------------------------------------------------
    # Assemble and cache
    # -----------------------------------------------------------------
    payload: dict[str, Any] = {
        "frameworks": frameworks_out,
        "top_risks": top_risks,
        "recent_drift": recent_drift,
        "open_issues": open_issues,
        "posture_score": posture_score,
        "connectors": connectors,
        "last_assessment": last_assessment,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cache_ttl_seconds": _DASHBOARD_CACHE_TTL,
    }

    get_cache().set(cache_key, payload, ttl=_DASHBOARD_CACHE_TTL)

    if ai:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        ai_svc = get_ai_service()
        if ai_svc.is_task_enabled(AITask.EXECUTIVE_REPORT):
            ai_context = {
                "posture_score": posture_score,
                "frameworks": frameworks_out,
                "top_risks": top_risks,
                "open_issues": open_issues,
            }
            ai_result = ai_svc.reason(AITask.EXECUTIVE_REPORT, context=ai_context)
            enhanced = dict(payload)
            enhanced["ai_narrative"] = ai_result.value if ai_result.ai_used else None
            if ai_result.ai_used:
                enhanced["ai_metadata"] = {
                    "model": ai_result.model,
                    "provider": ai_result.provider,
                    "latency_ms": ai_result.latency_ms,
                    "confidence": ai_result.confidence,
                }
            return enhanced

    return payload
