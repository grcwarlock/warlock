"""Risk analysis, vendor risk, policy coverage, audit simulation, and impact check routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission
from warlock.db.models import User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class RiskAnalyzeRequest(BaseModel):
    framework: str
    iterations: int = 10000
    ai: bool = False


class RiskScenarioResponse(BaseModel):
    name: str
    mean_ale: float
    var_95: float
    var_99: float
    control_effectiveness: float


class RiskPortfolioResponse(BaseModel):
    total_mean_ale: float
    total_var_95: float
    total_var_99: float
    scenario_count: int
    iterations: int


class RiskAnalysisResponse(BaseModel):
    framework: str
    scenarios: list[RiskScenarioResponse]
    portfolio: RiskPortfolioResponse


class RiskCacheStatsResponse(BaseModel):
    total_entries: int
    oldest_entry_age_hours: float | None
    entries_per_framework: dict[str, int]
    cache_hits: int
    cache_misses: int
    hit_rate: float | None


class VendorScoreResponse(BaseModel):
    vendor_name: str
    vendor_id: str
    overall_score: float
    risk_level: str
    issues_count: int
    criticality_score: float
    security_posture_score: float
    assessment_currency_score: float
    sla_compliance_score: float
    recommendations: list[str]


class PolicyCoverageResponse(BaseModel):
    framework: str
    total_controls: int
    controls_with_policy: int
    coverage_pct: float
    gaps: list[str]
    policy_map: dict[str, list[str]]


class PolicyGapsResponse(BaseModel):
    framework: str
    gaps: list[str]
    gap_count: int


class AuditSimulationRequest(BaseModel):
    framework: str
    target_date: str
    system_id: str | None = None


class FrameworkDiffRequest(BaseModel):
    old_version: str
    new_version: str


class ImpactCheckRequest(BaseModel):
    changed_files: list[str]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/risk/analyze")
def analyze_risk(
    req: RiskAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Run FAIR Monte Carlo risk quantification for a framework.

    Pass ``ai=true`` in the request body to append an AI-generated
    executive narrative that interprets the quantitative results.
    """
    # ABAC: verify user has access to the requested framework
    if current_user.allowed_frameworks and req.framework not in current_user.allowed_frameworks:
        raise HTTPException(status_code=403, detail="Access denied for this framework")

    from warlock.assessors.risk_engine import RiskEngine

    engine = RiskEngine(default_iterations=req.iterations)
    result = engine.analyze_framework_risk(db, req.framework, iterations=req.iterations)

    response = RiskAnalysisResponse(
        framework=req.framework,
        scenarios=[RiskScenarioResponse(**s) for s in result.get("scenarios", [])],
        portfolio=RiskPortfolioResponse(**result.get("portfolio", {})),
    )

    if req.ai:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        ai_svc = get_ai_service()
        if ai_svc.is_task_enabled(AITask.RISK_NARRATIVE):
            ai_context = {
                "framework": req.framework,
                "scenarios": result.get("scenarios", []),
                "portfolio": result.get("portfolio", {}),
            }
            ai_result = ai_svc.reason(AITask.RISK_NARRATIVE, context=ai_context)
            enriched = response.model_dump()
            enriched["ai_narrative"] = ai_result.value if ai_result.ai_used else None
            if ai_result.ai_used:
                enriched["ai_metadata"] = {
                    "model": ai_result.model,
                    "provider": ai_result.provider,
                    "latency_ms": ai_result.latency_ms,
                    "confidence": ai_result.confidence,
                }
            return enriched

    return response


@router.get("/risk/cache-stats", response_model=RiskCacheStatsResponse)
def risk_cache_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Return Monte Carlo cache statistics."""
    from warlock.assessors.risk_engine import RiskEngine

    engine = RiskEngine()
    stats = engine.get_cache_stats(db)
    return RiskCacheStatsResponse(**stats)


@router.get("/vendors/risk", response_model=list[VendorScoreResponse])
def vendor_risk_scores(
    provider: str = Query("securityscorecard"),
    threshold: float = Query(60.0, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Score and monitor vendor risk from SecurityScorecard data."""
    from warlock.assessors.vendor_risk import VendorRiskEngine

    engine = VendorRiskEngine()
    scores = engine.monitor_all(db, provider=provider, high_risk_threshold=threshold)

    return [
        VendorScoreResponse(
            vendor_name=s.vendor_name,
            vendor_id=s.vendor_id,
            overall_score=s.overall_score,
            risk_level=s.risk_level,
            issues_count=s.issues_count,
            criticality_score=s.criticality_score,
            security_posture_score=s.security_posture_score,
            assessment_currency_score=s.assessment_currency_score,
            sla_compliance_score=s.sla_compliance_score,
            recommendations=s.recommendations,
        )
        for s in sorted(scores, key=lambda x: x.overall_score)
    ]


@router.get("/policies/coverage", response_model=PolicyCoverageResponse)
def policy_coverage(
    framework: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Score policy documentation coverage for a framework."""
    # ABAC: verify user has access to the requested framework
    if current_user.allowed_frameworks and framework not in current_user.allowed_frameworks:
        raise HTTPException(status_code=403, detail="Access denied for this framework")

    from warlock.assessors.policy_discovery import score_policy_coverage

    coverage = score_policy_coverage(db, framework)

    return PolicyCoverageResponse(
        framework=coverage.framework,
        total_controls=coverage.total_controls,
        controls_with_policy=coverage.controls_with_policy,
        coverage_pct=coverage.coverage_pct,
        gaps=coverage.gaps,
        policy_map=coverage.policy_map,
    )


@router.get("/policies/gaps", response_model=PolicyGapsResponse)
def policy_gaps(
    framework: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Identify controls with no policy documentation."""
    if current_user.allowed_frameworks and framework not in current_user.allowed_frameworks:
        raise HTTPException(status_code=403, detail="Access denied for this framework")

    from warlock.assessors.policy_discovery import identify_policy_gaps

    gaps = identify_policy_gaps(db, framework)

    return PolicyGapsResponse(
        framework=framework,
        gaps=gaps,
        gap_count=len(gaps),
    )


@router.post("/audit-simulation")
def run_audit_simulation(
    req: AuditSimulationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Simulate what an auditor would see at a future date."""
    if current_user.allowed_frameworks and req.framework not in current_user.allowed_frameworks:
        raise HTTPException(status_code=403, detail="Access denied for this framework")

    from warlock.assessors.simulation import AuditSimulator
    from datetime import datetime as dt, timezone as tz

    sim = AuditSimulator()
    target = dt.fromisoformat(req.target_date).replace(tzinfo=tz.utc)
    result = sim.simulate(db, req.framework, target, system_id=req.system_id)
    return {
        "projected_coverage": result.projected_coverage,
        "total_controls": result.total_controls,
        "stale_controls": result.stale_controls,
        "overdue_poams": result.overdue_poams,
        "expiring_acceptances": result.expiring_acceptances,
        "at_risk_controls": result.at_risk_controls,
    }


@router.post("/frameworks/diff")
def framework_diff_endpoint(
    req: FrameworkDiffRequest,
    current_user: User = Depends(require_permission("read")),
):
    """Compare two framework versions."""
    from warlock.frameworks.diff import FrameworkDiff

    differ = FrameworkDiff()
    result = differ.diff(req.old_version, req.new_version)
    return {
        "added": sorted(result.added_controls),
        "removed": sorted(result.removed_controls),
        "modified": sorted(result.modified_controls),
        "unchanged_count": len(result.unchanged_controls),
    }


@router.post("/impact-check")
def impact_check_endpoint(
    req: ImpactCheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Check compliance impact of changed assertion/policy files."""
    from warlock.assessors.impact import ComplianceImpactAnalyzer

    analyzer = ComplianceImpactAnalyzer()
    result = analyzer.analyze(db, req.changed_files)
    return {
        "affected_controls": result.affected_controls,
        "predicted_flips": [
            {
                "control": f.control,
                "framework": f.framework,
                "from_status": f.from_status,
                "to_status": f.to_status,
            }
            for f in result.predicted_flips
        ],
    }
