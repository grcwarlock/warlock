"""Analytics routes: expose CLI-only analytics as API endpoints.

Mirrors the query logic from compliance_views_cmd, security_posture_cmd,
comply_cmd, and correlate_cmd CLI modules.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission, apply_framework_scope
from warlock.db.models import (
    ConnectorRun,
    ControlMapping,
    ControlResult,
    Finding,
    Issue,
    POAM,
    SystemProfile,
    User,
)
from warlock.utils import ensure_aware

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ParetoFamilyResponse(BaseModel):
    rank: int
    framework: str
    family: str
    failures: int
    pct: float
    cumulative_pct: float


class ParetoResponse(BaseModel):
    total_failures: int
    families: list[ParetoFamilyResponse]


class OrgUnitPostureResponse(BaseModel):
    org_unit: str
    total: int
    compliant: int
    non_compliant: int
    score: float


class CatoDashboardItemResponse(BaseModel):
    system_name: str
    acronym: str | None
    authorization_status: str
    overall_impact: str | None
    framework_count: int
    compliant: int
    total: int
    score: float


class AIConfidenceBucketResponse(BaseModel):
    bucket: str
    count: int
    pct: float


class AIConfidenceResponse(BaseModel):
    total_ai_assessed: int
    avg_confidence: float | None
    buckets: list[AIConfidenceBucketResponse]


class ForecastResponse(BaseModel):
    framework: str | None
    current_score: float
    target_score: float
    monthly_projections: list[dict]


class PlatformHealthResponse(BaseModel):
    total_connectors: int
    successful: int
    failed: int
    partial: int
    total_events: int
    total_findings: int
    total_results: int
    health_score: float


class EncryptionStatusResponse(BaseModel):
    total_findings: int
    encryption_related: int
    coverage_pct: float
    items: list[dict]


class PatchComplianceResponse(BaseModel):
    total_findings: int
    patch_related: int
    by_severity: dict[str, dict]


class TTPMappingResponse(BaseModel):
    total_findings: int
    mapped_count: int
    techniques: list[dict]


class NetworkExposureResponse(BaseModel):
    total_findings: int
    exposure_count: int
    items: list[dict]


class ReadinessScoreResponse(BaseModel):
    framework: str | None
    score: float
    total: int
    compliant: int
    non_compliant: int
    partial: int
    not_assessed: int
    label: str


class MaturityLevelResponse(BaseModel):
    framework: str | None
    level: int
    label: str
    score: float
    details: dict


class QuickWinResponse(BaseModel):
    framework: str
    control_id: str
    severity: str
    status: str
    remediation_summary: str | None
    priority_score: float


class ComplianceDebtItemResponse(BaseModel):
    source: str
    id: str
    title: str
    age_days: int
    severity: str | None


class ComplianceDebtResponse(BaseModel):
    total_items: int
    items: list[ComplianceDebtItemResponse]


class GapAnalysisResponse(BaseModel):
    framework: str
    controls_mapped: int
    controls_assessed: int
    controls_unassessed: int
    non_compliant_count: int
    stale_evidence_count: int
    active_sources: int
    non_compliant_controls: list[str]
    unassessed_controls: list[str]
    stale_controls: list[str]


class BlastRadiusResponse(BaseModel):
    finding_id: str
    affected_frameworks: list[str]
    affected_controls: list[dict]
    total_control_results: int


class CoverageMatrixResponse(BaseModel):
    framework: str
    total_controls: int
    covered_controls: int
    coverage_pct: float
    controls: list[dict]


# ---------------------------------------------------------------------------
# Helpers (ported from CLI modules)
# ---------------------------------------------------------------------------

_SLA_DAYS: dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 90,
    "low": 180,
}

_SEVERITY_SCORE: dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 0,
}

_ENCRYPTION_KEYWORDS = [
    "encrypt",
    "kms",
    "tls",
    "ssl",
    "cipher",
    "aes",
    "rsa",
    "certificate",
    "key_rotation",
    "at_rest",
    "in_transit",
]

_PATCH_KEYWORDS = [
    "patch",
    "update",
    "upgrade",
    "cve",
    "hotfix",
    "security_update",
    "eol",
    "end_of_life",
    "outdated",
    "unsupported",
]

_NETWORK_KEYWORDS = [
    "exposed",
    "public",
    "open_port",
    "security_group",
    "firewall",
    "ingress",
    "egress",
    "0.0.0.0",
    "internet_facing",
]

_TTP_KEYWORDS = [
    "lateral",
    "privilege_escalation",
    "exfiltration",
    "persistence",
    "credential",
    "brute_force",
    "phishing",
    "c2",
    "command_and_control",
    "discovery",
    "execution",
    "defense_evasion",
]


def _detail_str(detail) -> str:
    """Safely convert detail JSON to lowercase string for keyword searching."""
    import json

    if detail is None:
        return ""
    if isinstance(detail, str):
        return detail.lower()
    return json.dumps(detail, default=str).lower()


def _detail_contains(detail, keywords: list[str]) -> bool:
    text = _detail_str(detail)
    return any(kw in text for kw in keywords)


def _extract_family(ctrl_id: str) -> str:
    """Extract control family from control ID."""
    parts = ctrl_id.split("-", 1)
    if len(parts) > 1:
        return parts[0]
    dot_parts = ctrl_id.split(".", 2)
    return ".".join(dot_parts[:2]) if len(dot_parts) > 2 else dot_parts[0]


def _score_pct(compliant: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(compliant / total * 100, 1)


def _score_label(score: float) -> str:
    if score >= 80:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Poor"
    return "Critical"


def _maturity_level(score: float) -> tuple[int, str]:
    if score >= 90:
        return 5, "Optimizing"
    if score >= 75:
        return 4, "Managed"
    if score >= 55:
        return 3, "Defined"
    if score >= 30:
        return 2, "Developing"
    return 1, "Initial"


# ---------------------------------------------------------------------------
# Compliance Views
# ---------------------------------------------------------------------------


@router.get("/analytics/pareto", response_model=ParetoResponse)
def analytics_pareto(
    framework: str | None = Query(None),
    top: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Pareto analysis: top control families causing the most failures."""
    query = db.query(
        ControlResult.framework,
        ControlResult.control_id,
    ).filter(ControlResult.status == "non_compliant")

    if framework:
        query = query.filter(ControlResult.framework == framework)
    query = apply_framework_scope(query, ControlResult, current_user)
    rows = query.limit(500_000).all()

    if not rows:
        return ParetoResponse(total_failures=0, families=[])

    family_counts: Counter[tuple[str, str]] = Counter()
    for fw, ctrl_id in rows:
        family = _extract_family(ctrl_id)
        family_counts[(fw, family)] += 1

    total_failures = sum(family_counts.values())
    sorted_families = family_counts.most_common(top)

    families = []
    cumulative = 0.0
    for rank, ((fw, family), count) in enumerate(sorted_families, 1):
        pct = round(count / total_failures * 100, 1)
        cumulative += pct
        families.append(
            ParetoFamilyResponse(
                rank=rank,
                framework=fw,
                family=family,
                failures=count,
                pct=pct,
                cumulative_pct=round(cumulative, 1),
            )
        )

    return ParetoResponse(total_failures=total_failures, families=families)


@router.get("/analytics/by-org-unit", response_model=list[OrgUnitPostureResponse])
def analytics_by_org_unit(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Compliance posture breakdown by system profile (org unit)."""
    profiles = (
        db.query(SystemProfile)
        .filter(
            SystemProfile.is_active == True  # noqa: E712
        )
        .all()
    )

    results = []
    for sp in profiles:
        q = db.query(ControlResult).filter(ControlResult.system_profile_id == sp.id)
        q = apply_framework_scope(q, ControlResult, current_user)
        rows = q.all()
        total = len(rows)
        compliant = sum(1 for r in rows if r.status == "compliant")
        non_compliant = sum(1 for r in rows if r.status == "non_compliant")
        results.append(
            OrgUnitPostureResponse(
                org_unit=sp.name,
                total=total,
                compliant=compliant,
                non_compliant=non_compliant,
                score=_score_pct(compliant, total),
            )
        )

    return sorted(results, key=lambda x: x.score, reverse=True)


@router.get(
    "/analytics/cato-dashboard",
    response_model=list[CatoDashboardItemResponse],
)
def analytics_cato_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """ATO health dashboard per system profile."""
    profiles = (
        db.query(SystemProfile)
        .filter(
            SystemProfile.is_active == True  # noqa: E712
        )
        .all()
    )

    items = []
    for sp in profiles:
        q = db.query(ControlResult).filter(ControlResult.system_profile_id == sp.id)
        q = apply_framework_scope(q, ControlResult, current_user)
        rows = q.all()
        total = len(rows)
        compliant = sum(1 for r in rows if r.status == "compliant")
        items.append(
            CatoDashboardItemResponse(
                system_name=sp.name,
                acronym=sp.acronym,
                authorization_status=sp.authorization_status or "unknown",
                overall_impact=sp.overall_impact,
                framework_count=len(sp.frameworks or []),
                compliant=compliant,
                total=total,
                score=_score_pct(compliant, total),
            )
        )

    return items


@router.get("/analytics/ai-confidence", response_model=AIConfidenceResponse)
def analytics_ai_confidence(
    buckets: int = Query(10, ge=2, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """AI assessment confidence distribution."""
    q = db.query(ControlResult.ai_confidence).filter(ControlResult.ai_confidence.isnot(None))
    q = apply_framework_scope(q, ControlResult, current_user)
    rows = q.all()

    if not rows:
        return AIConfidenceResponse(total_ai_assessed=0, avg_confidence=None, buckets=[])

    confidences = [r.ai_confidence for r in rows]
    total = len(confidences)
    avg = round(sum(confidences) / total, 3)

    step = 1.0 / buckets
    bucket_counts: dict[str, int] = {}
    for i in range(buckets):
        low = round(i * step, 2)
        high = round((i + 1) * step, 2)
        label = f"{low:.2f}-{high:.2f}"
        bucket_counts[label] = sum(1 for c in confidences if low <= c < high)
    # Include 1.0 in last bucket
    last_key = list(bucket_counts.keys())[-1]
    bucket_counts[last_key] += sum(1 for c in confidences if c == 1.0)

    bucket_list = [
        AIConfidenceBucketResponse(
            bucket=label,
            count=count,
            pct=round(count / total * 100, 1) if total else 0,
        )
        for label, count in bucket_counts.items()
    ]

    return AIConfidenceResponse(
        total_ai_assessed=total,
        avg_confidence=avg,
        buckets=bucket_list,
    )


@router.get("/analytics/forecast", response_model=ForecastResponse)
def analytics_forecast(
    framework: str | None = Query(None),
    months: int = Query(6, ge=1, le=24),
    target_score: float = Query(80.0, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Compliance forecast based on current trend."""
    q = db.query(ControlResult)
    if framework:
        q = q.filter(ControlResult.framework == framework)
    q = apply_framework_scope(q, ControlResult, current_user)
    results = q.all()

    total = len(results)
    if not total:
        return ForecastResponse(
            framework=framework,
            current_score=0.0,
            target_score=target_score,
            monthly_projections=[],
        )

    compliant = sum(1 for r in results if r.status == "compliant")
    current_score = _score_pct(compliant, total)

    # Simple linear projection
    projections = []
    gap = target_score - current_score
    monthly_improvement = gap / months if months > 0 else 0.0
    for m in range(1, months + 1):
        projected = min(current_score + monthly_improvement * m, 100.0)
        projections.append(
            {
                "month": m,
                "projected_score": round(projected, 1),
                "delta": round(projected - current_score, 1),
            }
        )

    return ForecastResponse(
        framework=framework,
        current_score=current_score,
        target_score=target_score,
        monthly_projections=projections,
    )


@router.get(
    "/analytics/platform-health",
    response_model=PlatformHealthResponse,
)
def analytics_platform_health(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Connector and pipeline health summary."""
    runs = db.query(ConnectorRun).all()
    total_connectors = len(runs)
    successful = sum(1 for r in runs if r.status == "success")
    failed = sum(1 for r in runs if r.status == "error")
    partial = sum(1 for r in runs if r.status == "partial")
    total_events = sum(r.event_count or 0 for r in runs)

    total_findings = db.query(Finding).count()
    total_results = db.query(ControlResult).count()

    health_score = _score_pct(successful, total_connectors)

    return PlatformHealthResponse(
        total_connectors=total_connectors,
        successful=successful,
        failed=failed,
        partial=partial,
        total_events=total_events,
        total_findings=total_findings,
        total_results=total_results,
        health_score=health_score,
    )


# ---------------------------------------------------------------------------
# Security Posture
# ---------------------------------------------------------------------------


@router.get(
    "/analytics/encryption-status",
    response_model=EncryptionStatusResponse,
)
def analytics_encryption_status(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Encryption coverage across findings."""
    q = db.query(Finding)
    q = apply_framework_scope(q, Finding, current_user)
    findings = q.limit(100_000).all()

    encryption_items = []
    for f in findings:
        if _detail_contains(f.detail, _ENCRYPTION_KEYWORDS):
            encryption_items.append(
                {
                    "id": f.id[:8],
                    "title": f.title,
                    "severity": f.severity,
                    "source": f.source,
                    "resource_type": f.resource_type,
                }
            )

    total = len(findings)
    enc_count = len(encryption_items)

    return EncryptionStatusResponse(
        total_findings=total,
        encryption_related=enc_count,
        coverage_pct=round(enc_count / total * 100, 1) if total else 0.0,
        items=encryption_items[:limit],
    )


@router.get(
    "/analytics/patch-compliance",
    response_model=PatchComplianceResponse,
)
def analytics_patch_compliance(
    severity: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Patch SLA compliance across findings."""
    q = db.query(Finding)
    if severity:
        q = q.filter(Finding.severity == severity)
    q = apply_framework_scope(q, Finding, current_user)
    findings = q.limit(100_000).all()

    patch_findings = [f for f in findings if _detail_contains(f.detail, _PATCH_KEYWORDS)]
    total = len(findings)
    patch_count = len(patch_findings)

    by_severity: dict[str, dict] = {}
    for f in patch_findings:
        sev = (f.severity or "unknown").lower()
        if sev not in by_severity:
            by_severity[sev] = {"count": 0, "sla_days": _SLA_DAYS.get(sev, 180)}
        by_severity[sev]["count"] += 1

    return PatchComplianceResponse(
        total_findings=total,
        patch_related=patch_count,
        by_severity=by_severity,
    )


@router.get("/analytics/ttp-mapping", response_model=TTPMappingResponse)
def analytics_ttp_mapping(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """MITRE ATT&CK TTP mapping across findings."""
    q = db.query(Finding)
    q = apply_framework_scope(q, Finding, current_user)
    findings = q.limit(100_000).all()

    techniques: dict[str, int] = defaultdict(int)
    mapped = 0
    for f in findings:
        text = _detail_str(f.detail)
        for kw in _TTP_KEYWORDS:
            if kw in text:
                techniques[kw] += 1
                mapped += 1
                break

    technique_list = sorted(
        [{"technique": k, "count": v} for k, v in techniques.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:limit]

    return TTPMappingResponse(
        total_findings=len(findings),
        mapped_count=mapped,
        techniques=technique_list,
    )


@router.get(
    "/analytics/network-exposure",
    response_model=NetworkExposureResponse,
)
def analytics_network_exposure(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Network exposure summary across findings."""
    q = db.query(Finding)
    q = apply_framework_scope(q, Finding, current_user)
    findings = q.limit(100_000).all()

    exposure_items = []
    for f in findings:
        if _detail_contains(f.detail, _NETWORK_KEYWORDS):
            exposure_items.append(
                {
                    "id": f.id[:8],
                    "title": f.title,
                    "severity": f.severity,
                    "source": f.source,
                    "resource_id": f.resource_id,
                }
            )

    return NetworkExposureResponse(
        total_findings=len(findings),
        exposure_count=len(exposure_items),
        items=exposure_items[:limit],
    )


# ---------------------------------------------------------------------------
# Comply
# ---------------------------------------------------------------------------


@router.get(
    "/analytics/readiness-score",
    response_model=ReadinessScoreResponse,
)
def analytics_readiness_score(
    framework: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """0-100 readiness score for a framework."""
    q = db.query(ControlResult)
    if framework:
        q = q.filter(ControlResult.framework == framework)
    q = apply_framework_scope(q, ControlResult, current_user)
    results = q.all()

    total = len(results)
    if not total:
        return ReadinessScoreResponse(
            framework=framework,
            score=0.0,
            total=0,
            compliant=0,
            non_compliant=0,
            partial=0,
            not_assessed=0,
            label="No data",
        )

    compliant = sum(1 for r in results if r.status == "compliant")
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    partial = sum(1 for r in results if r.status == "partial")
    not_assessed = sum(1 for r in results if r.status == "not_assessed")

    score = _score_pct(compliant, total)

    return ReadinessScoreResponse(
        framework=framework,
        score=score,
        total=total,
        compliant=compliant,
        non_compliant=non_compliant,
        partial=partial,
        not_assessed=not_assessed,
        label=_score_label(score),
    )


@router.get(
    "/analytics/maturity-model",
    response_model=MaturityLevelResponse,
)
def analytics_maturity_model(
    framework: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Maturity level assessment (1-5 scale)."""
    q = db.query(ControlResult)
    if framework:
        q = q.filter(ControlResult.framework == framework)
    q = apply_framework_scope(q, ControlResult, current_user)
    results = q.all()

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    score = _score_pct(compliant, total)
    level, label = _maturity_level(score)

    return MaturityLevelResponse(
        framework=framework,
        level=level,
        label=label,
        score=score,
        details={
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": sum(1 for r in results if r.status == "non_compliant"),
            "partial": sum(1 for r in results if r.status == "partial"),
        },
    )


@router.get("/analytics/quick-wins", response_model=list[QuickWinResponse])
def analytics_quick_wins(
    framework: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Prioritized quick wins: non-compliant controls sorted by fix impact."""
    q = db.query(ControlResult).filter(ControlResult.status.in_(["non_compliant", "partial"]))
    if framework:
        q = q.filter(ControlResult.framework == framework)
    q = apply_framework_scope(q, ControlResult, current_user)
    results = q.limit(10_000).all()

    wins = []
    for r in results:
        priority = _SEVERITY_SCORE.get((r.severity or "").lower(), 0)
        wins.append(
            QuickWinResponse(
                framework=r.framework,
                control_id=r.control_id,
                severity=r.severity,
                status=r.status,
                remediation_summary=r.remediation_summary,
                priority_score=float(priority),
            )
        )

    wins.sort(key=lambda x: x.priority_score, reverse=True)
    return wins[:limit]


@router.get(
    "/analytics/compliance-debt",
    response_model=ComplianceDebtResponse,
)
def analytics_compliance_debt(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Overdue compliance items across issues and POAMs."""
    now = datetime.now(timezone.utc)
    items: list[ComplianceDebtItemResponse] = []

    # Overdue issues
    overdue_issues = (
        db.query(Issue)
        .filter(
            Issue.status.notin_(["closed", "verified", "risk_accepted"]),
            Issue.due_date.isnot(None),
            Issue.due_date < now,
        )
        .all()
    )

    for iss in overdue_issues:
        due = ensure_aware(iss.due_date)
        age = (now - due).days
        items.append(
            ComplianceDebtItemResponse(
                source="issue",
                id=iss.id[:8],
                title=iss.title[:80] if iss.title else "",
                age_days=age,
                severity=iss.priority,
            )
        )

    # Overdue POAMs
    overdue_poams = (
        db.query(POAM)
        .filter(
            POAM.status.notin_(["completed", "verified", "cancelled"]),
            POAM.scheduled_completion.isnot(None),
            POAM.scheduled_completion < now,
        )
        .all()
    )

    for p in overdue_poams:
        due = ensure_aware(p.scheduled_completion)
        age = (now - due).days
        items.append(
            ComplianceDebtItemResponse(
                source="poam",
                id=p.id[:8],
                title=(p.weakness_description or "")[:80],
                age_days=age,
                severity=p.risk_level,
            )
        )

    items.sort(key=lambda x: x.age_days, reverse=True)

    return ComplianceDebtResponse(total_items=len(items), items=items)


# ---------------------------------------------------------------------------
# Correlate
# ---------------------------------------------------------------------------


@router.get("/analytics/gap-analysis", response_model=GapAnalysisResponse)
def analytics_gap_analysis(
    framework: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Comprehensive gap analysis for a framework."""
    if current_user.allowed_frameworks and framework not in current_user.allowed_frameworks:
        raise HTTPException(status_code=403, detail="Access denied for this framework")

    stale_hours = 24 * 7

    mapped = set(
        r.control_id
        for r in db.query(ControlMapping.control_id)
        .filter(ControlMapping.framework == framework)
        .distinct()
        .all()
    )

    assessed = set(
        r.control_id
        for r in db.query(ControlResult.control_id)
        .filter(ControlResult.framework == framework)
        .distinct()
        .all()
    )

    non_compliant = set(
        r.control_id
        for r in db.query(ControlResult.control_id)
        .filter(
            ControlResult.framework == framework,
            ControlResult.status == "non_compliant",
        )
        .distinct()
        .all()
    )

    cutoff = datetime.now(timezone.utc) - timedelta(hours=stale_hours)
    recent_mappings = set(
        r.control_id
        for r in db.query(ControlMapping.control_id)
        .join(Finding, Finding.id == ControlMapping.finding_id)
        .filter(
            ControlMapping.framework == framework,
            Finding.observed_at >= cutoff,
        )
        .distinct()
        .all()
    )
    stale_controls = mapped - recent_mappings

    sources = set(
        r.source
        for r in db.query(Finding.source)
        .join(ControlMapping, ControlMapping.finding_id == Finding.id)
        .filter(ControlMapping.framework == framework)
        .distinct()
        .all()
    )

    return GapAnalysisResponse(
        framework=framework,
        controls_mapped=len(mapped),
        controls_assessed=len(assessed),
        controls_unassessed=len(mapped - assessed),
        non_compliant_count=len(non_compliant),
        stale_evidence_count=len(stale_controls),
        active_sources=len(sources),
        non_compliant_controls=sorted(non_compliant),
        unassessed_controls=sorted(mapped - assessed),
        stale_controls=sorted(stale_controls),
    )


@router.get(
    "/analytics/blast-radius",
    response_model=BlastRadiusResponse,
)
def analytics_blast_radius(
    finding_id: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Blast radius: which frameworks and controls are affected by a finding."""
    mappings = db.query(ControlMapping).filter(ControlMapping.finding_id == finding_id).all()

    if not mappings:
        raise HTTPException(status_code=404, detail="No mappings for this finding")

    frameworks = set()
    controls = []
    for m in mappings:
        frameworks.add(m.framework)
        result = (
            db.query(ControlResult)
            .filter(
                ControlResult.finding_id == finding_id,
                ControlResult.control_mapping_id == m.id,
            )
            .first()
        )
        controls.append(
            {
                "framework": m.framework,
                "control_id": m.control_id,
                "status": result.status if result else "not_assessed",
            }
        )

    total_results = db.query(ControlResult).filter(ControlResult.finding_id == finding_id).count()

    return BlastRadiusResponse(
        finding_id=finding_id,
        affected_frameworks=sorted(frameworks),
        affected_controls=controls,
        total_control_results=total_results,
    )


@router.get(
    "/analytics/coverage-matrix",
    response_model=CoverageMatrixResponse,
)
def analytics_coverage_matrix(
    framework: str = Query(...),
    limit_controls: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Framework coverage matrix: control-level assessment status."""
    if current_user.allowed_frameworks and framework not in current_user.allowed_frameworks:
        raise HTTPException(status_code=403, detail="Access denied for this framework")

    results = (
        db.query(ControlResult.control_id, ControlResult.status)
        .filter(ControlResult.framework == framework)
        .limit(limit_controls * 50)
        .all()
    )

    control_status: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for ctrl_id, st in results:
        control_status[ctrl_id][st] += 1

    controls = []
    for ctrl_id, statuses in sorted(control_status.items())[:limit_controls]:
        total = sum(statuses.values())
        compliant = statuses.get("compliant", 0)
        controls.append(
            {
                "control_id": ctrl_id,
                "total_results": total,
                "compliant": compliant,
                "non_compliant": statuses.get("non_compliant", 0),
                "partial": statuses.get("partial", 0),
                "score": _score_pct(compliant, total),
            }
        )

    total_controls = len(control_status)
    covered = sum(1 for c in controls if c["compliant"] > 0)

    return CoverageMatrixResponse(
        framework=framework,
        total_controls=total_controls,
        covered_controls=covered,
        coverage_pct=_score_pct(covered, total_controls),
        controls=controls,
    )
