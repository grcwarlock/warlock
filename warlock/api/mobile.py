"""Compact mobile-friendly API endpoints.

Provides lightweight JSON payloads optimised for mobile clients:

- ``GET /api/v1/mobile/summary``   -- compliance posture at a glance
- ``GET /api/v1/mobile/alerts``    -- recent actionable alerts
- ``GET /api/v1/mobile/approvals`` -- pending approvals (POA&M, exceptions)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from warlock.api.deps import (
    apply_framework_scope,
    apply_source_scope,
    get_db,
    require_permission,
)
from warlock.db.models import POAM, Alert, ControlResult, User
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

router = APIRouter(prefix="/mobile", tags=["mobile"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class MobileSummaryResponse(BaseModel):
    """High-level compliance posture for dashboard cards."""

    total_controls: int = 0
    compliant: int = 0
    non_compliant: int = 0
    partial: int = 0
    not_assessed: int = 0
    compliance_pct: float = 0.0
    open_alerts: int = 0
    pending_approvals: int = 0
    last_pipeline_run: str | None = None
    timestamp: str


class MobileAlertItem(BaseModel):
    id: str
    title: str
    severity: str
    category: str | None = None
    created_at: str | None = None


class MobileAlertsResponse(BaseModel):
    alerts: list[MobileAlertItem]
    total: int


class MobileApprovalItem(BaseModel):
    id: str
    title: str
    type: str  # "poam" | "exception"
    status: str
    created_at: str | None = None


class MobileApprovalsResponse(BaseModel):
    approvals: list[MobileApprovalItem]
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dt_str(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    dt = ensure_aware(dt)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/summary", response_model=MobileSummaryResponse)
def mobile_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
) -> MobileSummaryResponse:
    """Compact compliance posture summary for mobile dashboard."""
    # Control status counts (scoped to user's allowed frameworks)
    cr_query = apply_framework_scope(db.query(ControlResult), ControlResult, current_user)
    status_counts = cr_query.with_entities(
        func.count().label("total"),
        func.sum(case((ControlResult.status == "compliant", 1), else_=0)).label("compliant"),
        func.sum(case((ControlResult.status == "non_compliant", 1), else_=0)).label(
            "non_compliant"
        ),
        func.sum(case((ControlResult.status == "partial", 1), else_=0)).label("partial"),
        func.sum(case((ControlResult.status == "not_assessed", 1), else_=0)).label("not_assessed"),
    ).first()

    total = status_counts.total or 0
    compliant = status_counts.compliant or 0
    non_compliant = status_counts.non_compliant or 0
    partial = status_counts.partial or 0
    not_assessed = status_counts.not_assessed or 0

    assessed = total - not_assessed
    compliance_pct = (compliant / assessed * 100.0) if assessed > 0 else 0.0

    # Open alerts (framework-scoped)
    alerts_q = apply_framework_scope(db.query(Alert), Alert, current_user)
    alerts_q = apply_source_scope(alerts_q, Alert, current_user)
    open_alerts = alerts_q.filter(Alert.status.in_(["open", "triggered"])).count() or 0

    # Pending approvals (POA&Ms in draft/open) — framework-scoped
    poam_q = apply_framework_scope(db.query(POAM), POAM, current_user)
    pending_approvals = poam_q.filter(POAM.status.in_(["draft", "open"])).count() or 0

    return MobileSummaryResponse(
        total_controls=total,
        compliant=compliant,
        non_compliant=non_compliant,
        partial=partial,
        not_assessed=not_assessed,
        compliance_pct=round(compliance_pct, 1),
        open_alerts=open_alerts,
        pending_approvals=pending_approvals,
        last_pipeline_run=None,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/alerts", response_model=MobileAlertsResponse)
def mobile_alerts(
    limit: int = Query(default=20, le=100, ge=1),
    severity: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
) -> MobileAlertsResponse:
    """Recent alerts in compact format for mobile notification list."""
    q = apply_framework_scope(db.query(Alert), Alert, current_user)
    q = apply_source_scope(q, Alert, current_user)
    q = q.filter(Alert.status.in_(["open", "triggered"]))
    if severity:
        q = q.filter(Alert.severity == severity)
    q = q.order_by(Alert.created_at.desc())

    total = q.count()
    rows = q.limit(limit).all()

    items = [
        MobileAlertItem(
            id=a.id,
            title=a.title or "",
            severity=a.severity or "medium",
            category=a.category,
            created_at=_dt_str(a.created_at),
        )
        for a in rows
    ]

    return MobileAlertsResponse(alerts=items, total=total)


@router.get("/approvals", response_model=MobileApprovalsResponse)
def mobile_approvals(
    limit: int = Query(default=20, le=100, ge=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
) -> MobileApprovalsResponse:
    """Pending approval items (POA&Ms, exceptions) for mobile action queue."""
    # POA&Ms needing review (framework-scoped)
    poams = (
        apply_framework_scope(db.query(POAM), POAM, current_user)
        .filter(POAM.status.in_(["draft", "open"]))
        .order_by(POAM.created_at.desc())
        .limit(limit)
        .all()
    )

    items: list[MobileApprovalItem] = []
    for p in poams:
        items.append(
            MobileApprovalItem(
                id=p.id,
                title=getattr(p, "title", None) or f"POA&M {p.id[:8]}",
                type="poam",
                status=p.status,
                created_at=_dt_str(p.created_at),
            )
        )

    return MobileApprovalsResponse(approvals=items, total=len(items))
