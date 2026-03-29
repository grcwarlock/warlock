"""Business continuity planning and disaster recovery routes.

Mirrors warlock/cli/bcp_cmd.py using SystemProfile for BIA and
AuditComment for DR test results.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, get_pagination, require_permission
from warlock.api.routers.schemas import PaginatedResponse
from warlock.db.models import AuditComment, SystemProfile, User

router = APIRouter()
log = logging.getLogger(__name__)

_IMPACT_ORDER = {"high": 3, "moderate": 2, "medium": 2, "low": 1, "": 0}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class BCPPlanResponse(BaseModel):
    id: str
    name: str
    acronym: str | None = None
    overall_impact: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    deployment_model: str | None = None
    authorization_status: str | None = None
    system_owner: str | None = None


class DRReadinessResponse(BaseModel):
    total_systems: int
    high_impact: int
    moderate_impact: int
    low_impact: int
    authorized: int
    not_authorized: int
    dr_tests_recorded: int
    readiness_score: float


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/bcp/plans", response_model=PaginatedResponse)
def list_bcp_plans(
    criticality: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List BCP plans (system profiles with impact categorization)."""
    limit, offset = pagination
    q = db.query(SystemProfile).filter(
        SystemProfile.is_active == True  # noqa: E712
    )
    if criticality:
        q = q.filter(SystemProfile.overall_impact == criticality)

    q = q.order_by(SystemProfile.name)
    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    # Sort by impact severity
    rows_sorted = sorted(
        rows,
        key=lambda s: _IMPACT_ORDER.get((s.overall_impact or "").lower(), 0),
        reverse=True,
    )

    items = [
        BCPPlanResponse(
            id=s.id,
            name=s.name,
            acronym=s.acronym,
            overall_impact=s.overall_impact,
            confidentiality_impact=s.confidentiality_impact,
            integrity_impact=s.integrity_impact,
            availability_impact=s.availability_impact,
            deployment_model=s.deployment_model,
            authorization_status=s.authorization_status,
            system_owner=s.system_owner,
        ).model_dump()
        for s in rows_sorted
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/bcp/dr-readiness", response_model=DRReadinessResponse)
def dr_readiness(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Disaster recovery readiness summary."""
    systems = (
        db.query(SystemProfile)
        .filter(
            SystemProfile.is_active == True  # noqa: E712
        )
        .all()
    )

    total = len(systems)
    high = sum(1 for s in systems if (s.overall_impact or "").lower() == "high")
    moderate = sum(1 for s in systems if (s.overall_impact or "").lower() in ("moderate", "medium"))
    low = sum(1 for s in systems if (s.overall_impact or "").lower() == "low")
    authorized = sum(1 for s in systems if (s.authorization_status or "").lower() == "authorized")
    not_authorized = total - authorized

    # Count DR test records from audit comments
    dr_tests = db.query(AuditComment).filter(AuditComment.target_type == "dr_test").count()

    # Simple readiness heuristic
    readiness = 0.0
    if total:
        auth_pct = authorized / total * 50
        test_pct = min(dr_tests / max(total, 1), 1.0) * 50
        readiness = round(auth_pct + test_pct, 1)

    return DRReadinessResponse(
        total_systems=total,
        high_impact=high,
        moderate_impact=moderate,
        low_impact=low,
        authorized=authorized,
        not_authorized=not_authorized,
        dr_tests_recorded=dr_tests,
        readiness_score=readiness,
    )
