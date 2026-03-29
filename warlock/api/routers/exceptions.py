"""Policy exception routes.

Policy exceptions are stored as PolicyOverride records with lifecycle
metadata in AuditEntry extra blobs, mirroring warlock/cli/exceptions_cmd.py.
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
from warlock.db.models import AuditEntry, PolicyOverride, User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ExceptionCreateRequest(BaseModel):
    name: str
    description: str | None = None
    justification: str | None = None
    expiry_days: int = 90
    scope: str | None = None


class ExceptionUpdateRequest(BaseModel):
    description: str | None = None
    is_active: bool | None = None


class ExceptionResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    is_active: bool
    status: str
    justification: str | None = None
    expiry: str | None = None
    created_by: str | None = None
    created_at: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_exception_meta(db: Session, exception_id: str) -> dict:
    """Return the AuditEntry extra blob for a PolicyOverride."""
    entry = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.action == "policy_exception",
            AuditEntry.entity_type == "exception",
            AuditEntry.entity_id == exception_id,
        )
        .order_by(AuditEntry.created_at.desc())
        .first()
    )
    return entry.extra if entry else {}


def _derive_status(meta: dict) -> str:
    stored = meta.get("status", "active")
    if stored in ("expired", "pending-renewal", "revoked"):
        return stored
    expiry_str = meta.get("expiry")
    if expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < datetime.now(timezone.utc):
                return "expired"
        except ValueError:
            pass
    return stored


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/exceptions", response_model=PaginatedResponse)
def list_exceptions(
    status: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List policy exceptions."""
    limit, offset = pagination
    q = db.query(PolicyOverride).order_by(PolicyOverride.created_at.desc())
    if status == "active":
        q = q.filter(PolicyOverride.is_active == True)  # noqa: E712
    elif status == "inactive":
        q = q.filter(PolicyOverride.is_active == False)  # noqa: E712

    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    items = []
    for r in rows:
        meta = _load_exception_meta(db, r.id)
        eff_status = _derive_status(meta)
        items.append(
            ExceptionResponse(
                id=r.id,
                name=r.name,
                description=r.description,
                is_active=r.is_active if r.is_active is not None else True,
                status=eff_status,
                justification=meta.get("justification"),
                expiry=meta.get("expiry"),
                created_by=r.created_by,
                created_at=_dt_str(r.created_at),
            ).model_dump()
        )

    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/exceptions",
    response_model=ExceptionResponse,
    status_code=201,
)
def create_exception(
    req: ExceptionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a new policy exception."""
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    exc_id = str(uuid.uuid4())
    expiry = now + timedelta(days=req.expiry_days)

    override = PolicyOverride(
        id=exc_id,
        name=req.name,
        description=req.description,
        policy_rego="# Exception placeholder",
        is_active=True,
        created_by=current_user.email,
        created_at=now,
    )
    db.add(override)

    # Store metadata in audit entry
    last = db.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1
    actor = f"api:{current_user.email}"
    payload = f"{seq}:{prev_hash}:policy_exception:{exc_id}:{actor}"
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action="policy_exception",
        entity_type="exception",
        entity_id=exc_id,
        actor=actor,
        extra={
            "status": "active",
            "justification": req.justification,
            "expiry": expiry.isoformat(),
            "scope": req.scope,
        },
        created_at=now,
    )
    db.add(audit)

    return ExceptionResponse(
        id=exc_id,
        name=req.name,
        description=req.description,
        is_active=True,
        status="active",
        justification=req.justification,
        expiry=expiry.isoformat(),
        created_by=current_user.email,
        created_at=_dt_str(now),
    )


@router.patch(
    "/exceptions/{exception_id}",
    response_model=ExceptionResponse,
)
def update_exception(
    exception_id: str,
    req: ExceptionUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Update a policy exception."""
    override = db.query(PolicyOverride).filter(PolicyOverride.id == exception_id).first()
    if not override:
        override = (
            db.query(PolicyOverride).filter(PolicyOverride.id.startswith(exception_id)).first()
        )
    if not override:
        raise HTTPException(status_code=404, detail="Exception not found")

    if req.description is not None:
        override.description = req.description
    if req.is_active is not None:
        override.is_active = req.is_active

    meta = _load_exception_meta(db, override.id)
    eff_status = _derive_status(meta)

    return ExceptionResponse(
        id=override.id,
        name=override.name,
        description=override.description,
        is_active=override.is_active if override.is_active is not None else True,
        status=eff_status,
        justification=meta.get("justification"),
        expiry=meta.get("expiry"),
        created_by=override.created_by,
        created_at=_dt_str(override.created_at),
    )
