"""Training routes: security awareness training status and campaigns.

Mirrors warlock/cli/training_cmd.py using the Personnel model.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, get_pagination, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import AuditEntry, Personnel, User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TrainingStatusResponse(BaseModel):
    total_personnel: int
    current: int
    overdue: int
    not_enrolled: int
    completion_rate: float
    by_department: list[dict]


class TrainingRecordResponse(BaseModel):
    id: str
    email: str
    full_name: str
    department: str | None = None
    training_status: str | None = None
    last_training_date: str | None = None
    phishing_score: float | None = None


class TrainingCampaignResponse(BaseModel):
    id: str
    name: str
    status: str
    total_assigned: int
    completed: int
    created_at: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/training/status",
    response_model=TrainingStatusResponse,
)
def training_status(
    department: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Training completion status aggregated by department."""
    q = db.query(Personnel).filter(
        Personnel.is_active == True  # noqa: E712
    )
    if department:
        q = q.filter(Personnel.department.ilike(f"%{department}%"))
    rows = q.all()

    total = len(rows)
    current = sum(1 for r in rows if r.training_status == "current")
    overdue = sum(1 for r in rows if r.training_status == "overdue")
    not_enrolled = sum(1 for r in rows if r.training_status in ("not_enrolled", None))

    completion_rate = round(current / total * 100, 1) if total else 0.0

    dept_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "current": 0, "overdue": 0}
    )
    for r in rows:
        dept = r.department or "Unknown"
        dept_counts[dept]["total"] += 1
        if r.training_status == "current":
            dept_counts[dept]["current"] += 1
        elif r.training_status == "overdue":
            dept_counts[dept]["overdue"] += 1

    by_department = [
        {
            "department": dept,
            "total": data["total"],
            "current": data["current"],
            "overdue": data["overdue"],
            "rate": round(data["current"] / data["total"] * 100, 1) if data["total"] else 0.0,
        }
        for dept, data in sorted(dept_counts.items())
    ]

    return TrainingStatusResponse(
        total_personnel=total,
        current=current,
        overdue=overdue,
        not_enrolled=not_enrolled,
        completion_rate=completion_rate,
        by_department=by_department,
    )


@router.get("/training/campaigns", response_model=PaginatedResponse)
def training_campaigns(
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List training campaigns from audit trail."""
    limit, offset = pagination
    q = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.action == "training_campaign",
            AuditEntry.entity_type == "training",
        )
        .order_by(AuditEntry.created_at.desc())
    )

    rows = q.all()

    items = []
    for r in rows:
        extra = r.extra or {}
        items.append(
            TrainingCampaignResponse(
                id=r.entity_id,
                name=extra.get("name", ""),
                status=extra.get("status", "active"),
                total_assigned=extra.get("total_assigned", 0),
                completed=extra.get("completed", 0),
                created_at=_dt_str(r.created_at),
            ).model_dump()
        )

    total = len(items)
    paged = items[offset : offset + limit]

    return PaginatedResponse(
        items=paged,
        total=total,
        limit=limit,
        offset=offset,
    )
