"""Reports routes: executive summary, KRI, board-level, and trend data."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import (
    get_db,
    require_permission,
    apply_framework_scope,
)
from warlock.db.models import (
    ControlResult,
    Finding,
    Issue,
    POAM,
    PostureSnapshot,
    User,
    Vendor,
)
from warlock.utils import ensure_aware

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ExecutiveReportResponse(BaseModel):
    framework: str | None
    posture_score: float
    total_controls: int
    compliant: int
    non_compliant: int
    partial: int
    open_issues: int
    total_findings: int


class KRIResponse(BaseModel):
    high_risk_findings: int
    overdue_poams: int
    non_compliant_controls: int
    open_critical_issues: int
    vendor_risk_count: int
    mean_time_to_remediate_days: float | None


class BoardSummaryResponse(BaseModel):
    overall_score: float
    frameworks: list[dict]
    risk_highlights: list[str]
    trend_direction: str


class TrendPointResponse(BaseModel):
    date: str
    framework: str
    score: float
    compliant: int
    total: int


class TrendResponse(BaseModel):
    points: list[TrendPointResponse]
    period_days: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/reports/executive",
    response_model=ExecutiveReportResponse,
)
def reports_executive(
    framework: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Executive compliance posture summary."""
    q = db.query(ControlResult)
    if framework:
        q = q.filter(ControlResult.framework == framework)
    q = apply_framework_scope(q, ControlResult, current_user)
    results = q.all()

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    non_compliant = sum(1 for r in results if r.status == "non_compliant")
    partial = sum(1 for r in results if r.status == "partial")
    score = round(compliant / total * 100, 1) if total else 0.0

    open_issues = db.query(Issue).filter(Issue.status.notin_(["closed", "verified"])).count()
    total_findings = db.query(Finding).count()

    return ExecutiveReportResponse(
        framework=framework,
        posture_score=score,
        total_controls=total,
        compliant=compliant,
        non_compliant=non_compliant,
        partial=partial,
        open_issues=open_issues,
        total_findings=total_findings,
    )


@router.get("/reports/kri", response_model=KRIResponse)
def reports_kri(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Key risk indicators across the platform."""
    now = datetime.now(timezone.utc)

    high_risk = db.query(Finding).filter(Finding.severity.in_(["critical", "high"])).count()

    overdue_poams = (
        db.query(POAM)
        .filter(
            POAM.status.notin_(["completed", "verified", "cancelled"]),
            POAM.scheduled_completion.isnot(None),
            POAM.scheduled_completion < now,
        )
        .count()
    )

    nc_controls = db.query(ControlResult).filter(ControlResult.status == "non_compliant").count()

    critical_issues = (
        db.query(Issue)
        .filter(
            Issue.status.notin_(["closed", "verified"]),
            Issue.priority.in_(["critical", "high"]),
        )
        .count()
    )

    vendor_risk = db.query(Vendor).filter(Vendor.risk_tier.in_(["critical", "high"])).count()

    # MTTR for closed issues
    closed = (
        db.query(Issue)
        .filter(
            Issue.status.in_(["closed", "verified"]),
            Issue.remediated_at.isnot(None),
            Issue.created_at.isnot(None),
        )
        .limit(1000)
        .all()
    )

    mttr = None
    if closed:
        durations = []
        for iss in closed:
            created = ensure_aware(iss.created_at)
            remediated = ensure_aware(iss.remediated_at)
            durations.append((remediated - created).total_seconds() / 86400)
        mttr = round(sum(durations) / len(durations), 1)

    return KRIResponse(
        high_risk_findings=high_risk,
        overdue_poams=overdue_poams,
        non_compliant_controls=nc_controls,
        open_critical_issues=critical_issues,
        vendor_risk_count=vendor_risk,
        mean_time_to_remediate_days=mttr,
    )


@router.get("/reports/board", response_model=BoardSummaryResponse)
def reports_board(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Board-level compliance summary across all frameworks."""
    q = db.query(ControlResult)
    q = apply_framework_scope(q, ControlResult, current_user)
    results = q.all()

    total = len(results)
    compliant = sum(1 for r in results if r.status == "compliant")
    overall_score = round(compliant / total * 100, 1) if total else 0.0

    # Per-framework breakdown
    fw_data: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "compliant": 0})
    for r in results:
        fw_data[r.framework]["total"] += 1
        if r.status == "compliant":
            fw_data[r.framework]["compliant"] += 1

    frameworks = []
    for fw, data in sorted(fw_data.items()):
        fw_total = data["total"]
        fw_compliant = data["compliant"]
        fw_score = round(fw_compliant / fw_total * 100, 1) if fw_total else 0.0
        frameworks.append(
            {
                "framework": fw,
                "score": fw_score,
                "total": fw_total,
                "compliant": fw_compliant,
            }
        )

    # Risk highlights
    highlights = []
    nc = sum(1 for r in results if r.status == "non_compliant")
    if nc > 0:
        highlights.append(f"{nc} non-compliant control results across all frameworks")

    overdue_poams = (
        db.query(POAM)
        .filter(
            POAM.status.notin_(["completed", "verified", "cancelled"]),
            POAM.scheduled_completion.isnot(None),
            POAM.scheduled_completion < datetime.now(timezone.utc),
        )
        .count()
    )
    if overdue_poams:
        highlights.append(f"{overdue_poams} overdue POA&M items")

    critical_issues = (
        db.query(Issue)
        .filter(
            Issue.status.notin_(["closed", "verified"]),
            Issue.priority == "critical",
        )
        .count()
    )
    if critical_issues:
        highlights.append(f"{critical_issues} open critical issues")

    # Simple trend direction
    trend = "stable"
    if overall_score >= 80:
        trend = "positive"
    elif overall_score < 50:
        trend = "negative"

    return BoardSummaryResponse(
        overall_score=overall_score,
        frameworks=frameworks,
        risk_highlights=highlights,
        trend_direction=trend,
    )


@router.get("/reports/trend", response_model=TrendResponse)
def reports_trend(
    framework: str | None = Query(None),
    days: int = Query(90, ge=7, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Compliance trend over time from posture snapshots."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    q = db.query(PostureSnapshot).filter(PostureSnapshot.captured_at >= cutoff)
    if framework:
        q = q.filter(PostureSnapshot.framework == framework)
    snapshots = q.order_by(PostureSnapshot.captured_at).limit(5000).all()

    points = []
    for s in snapshots:
        captured = ensure_aware(s.captured_at)
        total = (s.compliant or 0) + (s.non_compliant or 0) + (s.partial or 0)
        score = round(s.compliant / total * 100, 1) if total else 0.0
        points.append(
            TrendPointResponse(
                date=captured.strftime("%Y-%m-%d"),
                framework=s.framework,
                score=score,
                compliant=s.compliant or 0,
                total=total,
            )
        )

    return TrendResponse(points=points, period_days=days)
