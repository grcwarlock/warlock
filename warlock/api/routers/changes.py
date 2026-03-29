"""Change management routes.

Change requests use AuditEntry records with action='change_request'
and entity_type='change_mgmt', mirroring warlock/cli/change_mgmt_cmd.py.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, get_pagination, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import AuditEntry, ChangeRequest, User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ChangeCreateRequest(BaseModel):
    title: str
    description: str | None = None
    change_type: str = "normal"
    risk_level: str = "medium"
    rollback_plan: str | None = None


class ChangeResponse(BaseModel):
    id: str
    title: str
    description: str | None = None
    change_type: str | None = None
    risk_level: str | None = None
    status: str
    requester: str | None = None
    cab_decision: str | None = None
    created_at: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/changes", response_model=PaginatedResponse)
def list_changes(
    status: str | None = Query(None),
    change_type: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List change requests with pagination."""
    limit, offset = pagination
    q = db.query(ChangeRequest).order_by(ChangeRequest.created_at.desc())
    if status:
        q = q.filter(ChangeRequest.status == status)
    if change_type:
        q = q.filter(ChangeRequest.change_type == change_type)

    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    items = [
        ChangeResponse(
            id=r.id,
            title=r.title,
            description=r.description,
            change_type=r.change_type,
            risk_level=r.risk_level,
            status=r.status or "draft",
            requester=r.requester,
            cab_decision=r.cab_decision,
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


@router.get("/changes/{change_id}", response_model=ChangeResponse)
def get_change(
    change_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Get change request detail."""
    cr = db.query(ChangeRequest).filter(ChangeRequest.id == change_id).first()
    if not cr:
        cr = db.query(ChangeRequest).filter(ChangeRequest.id.startswith(change_id)).first()
    if not cr:
        raise HTTPException(status_code=404, detail="Change request not found")

    return ChangeResponse(
        id=cr.id,
        title=cr.title,
        description=cr.description,
        change_type=cr.change_type,
        risk_level=cr.risk_level,
        status=cr.status or "draft",
        requester=cr.requester,
        cab_decision=cr.cab_decision,
        created_at=_dt_str(cr.created_at),
    )


@router.post("/changes", response_model=ChangeResponse, status_code=201)
def create_change(
    req: ChangeCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a new change request."""
    now = datetime.now(timezone.utc)
    cr_id = str(uuid.uuid4())

    cr = ChangeRequest(
        id=cr_id,
        title=req.title,
        description=req.description,
        change_type=req.change_type,
        risk_level=req.risk_level,
        requester=current_user.email,
        status="draft",
        rollback_plan=req.rollback_plan,
        created_at=now,
    )
    db.add(cr)

    # Audit entry
    last = db.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1
    actor = f"api:{current_user.email}"
    payload = f"{seq}:{prev_hash}:change_created:{cr_id}:{actor}"
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action="change_request",
        entity_type="change_mgmt",
        entity_id=cr_id,
        actor=actor,
        extra={"change_type": req.change_type, "risk_level": req.risk_level},
        created_at=now,
    )
    db.add(audit)

    return ChangeResponse(
        id=cr.id,
        title=cr.title,
        description=cr.description,
        change_type=cr.change_type,
        risk_level=cr.risk_level,
        status="draft",
        requester=cr.requester,
        cab_decision=cr.cab_decision,
        created_at=_dt_str(cr.created_at),
    )
