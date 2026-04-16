"""Compliance calendar routes: obligations and deadlines."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import apply_framework_scope, get_db, get_pagination, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import ComplianceObligation, User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ObligationCreateRequest(BaseModel):
    title: str
    framework: str | None = None
    control_id: str | None = None
    obligation_type: str = "audit"
    frequency: str = "annual"
    next_due: str | None = None
    owner: str | None = None
    notes: str | None = None


class ObligationResponse(BaseModel):
    id: str
    title: str
    framework: str | None = None
    control_id: str | None = None
    obligation_type: str | None = None
    frequency: str | None = None
    next_due: str | None = None
    owner: str | None = None
    status: str
    completed_at: str | None = None
    notes: str | None = None
    created_at: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/calendar", response_model=PaginatedResponse)
def list_obligations(
    status: str | None = Query(None),
    framework: str | None = Query(None),
    obligation_type: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List compliance obligations / calendar items."""
    limit, offset = pagination
    q = apply_framework_scope(db.query(ComplianceObligation), ComplianceObligation, current_user)
    q = q.order_by(ComplianceObligation.next_due.asc())
    if status:
        q = q.filter(ComplianceObligation.status == status)
    if framework:
        q = q.filter(ComplianceObligation.framework == framework)
    if obligation_type:
        q = q.filter(ComplianceObligation.obligation_type == obligation_type)

    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    items = [
        ObligationResponse(
            id=r.id,
            title=r.title,
            framework=r.framework,
            control_id=r.control_id,
            obligation_type=r.obligation_type,
            frequency=r.frequency,
            next_due=_dt_str(r.next_due),
            owner=r.owner,
            status=r.status or "pending",
            completed_at=_dt_str(r.completed_at),
            notes=r.notes,
            created_at=_dt_str(r.created_at),
        ).model_dump()
        for r in rows
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/calendar", response_model=ObligationResponse, status_code=201)
def create_obligation(
    req: ObligationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a compliance obligation / calendar item."""
    # Enforce framework scope on create — user cannot create an obligation
    # for a framework outside their allowed_frameworks list.
    if req.framework and current_user.allowed_frameworks:
        if req.framework not in current_user.allowed_frameworks:
            raise HTTPException(
                status_code=403,
                detail=f"Not authorized to create obligations for framework {req.framework}",
            )

    now = datetime.now(timezone.utc)
    obl_id = str(uuid.uuid4())

    next_due_dt = None
    if req.next_due:
        try:
            next_due_dt = datetime.fromisoformat(req.next_due)
            if next_due_dt.tzinfo is None:
                next_due_dt = next_due_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid date format: {req.next_due}")

    obl = ComplianceObligation(
        id=obl_id,
        title=req.title,
        framework=req.framework,
        control_id=req.control_id,
        obligation_type=req.obligation_type,
        frequency=req.frequency,
        next_due=next_due_dt,
        owner=req.owner or current_user.email,
        status="pending",
        notes=req.notes,
        created_at=now,
    )
    db.add(obl)

    return ObligationResponse(
        id=obl.id,
        title=obl.title,
        framework=obl.framework,
        control_id=obl.control_id,
        obligation_type=obl.obligation_type,
        frequency=obl.frequency,
        next_due=_dt_str(obl.next_due),
        owner=obl.owner,
        status=obl.status or "pending",
        completed_at=None,
        notes=obl.notes,
        created_at=_dt_str(obl.created_at),
    )
