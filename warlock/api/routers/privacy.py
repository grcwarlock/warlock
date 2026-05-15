"""Privacy routes: DSARs, breaches, transfers, ROPA.

Privacy records are stored as AuditEntry rows with structured extra data,
mirroring warlock/cli/privacy_cmd.py. DataSilo model is used for ROPA.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, get_pagination, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import AuditEntry, DataSilo, User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DSARCreateRequest(BaseModel):
    subject_email: str
    request_type: str = "access"
    description: str | None = None


class DSARResponse(BaseModel):
    id: str
    subject_email: str
    request_type: str
    status: str
    created_at: str | None = None
    description: str | None = None


class BreachResponse(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    reported_at: str | None = None
    records_affected: int | None = None


class TransferResponse(BaseModel):
    id: str
    source_country: str
    destination_country: str
    mechanism: str
    status: str
    created_at: str | None = None


class ROPAEntryResponse(BaseModel):
    id: str
    name: str
    silo_type: str
    provider: str | None = None
    data_classification: str | None = None
    contains_pii: bool
    contains_phi: bool
    owner: str | None = None
    applicable_frameworks: list[str]


# ---------------------------------------------------------------------------
# Routes — DSARs
# ---------------------------------------------------------------------------


@router.get("/privacy/dsars", response_model=PaginatedResponse)
def list_dsars(
    status: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List Data Subject Access Requests."""
    limit, offset = pagination
    q = (
        db.query(AuditEntry)
        .filter(AuditEntry.entity_type == "dsar")
        .order_by(AuditEntry.created_at.desc())
    )

    rows = q.all()

    items = []
    for r in rows:
        extra = r.extra or {}
        eff_status = extra.get("status", "open")
        if status and eff_status != status:
            continue
        items.append(
            DSARResponse(
                id=r.entity_id,
                subject_email=extra.get("subject_email", ""),
                request_type=extra.get("request_type", "access"),
                status=eff_status,
                created_at=_dt_str(r.created_at),
                description=extra.get("description"),
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


@router.post(
    "/privacy/dsars",
    response_model=DSARResponse,
    status_code=201,
)
def create_dsar(
    req: DSARCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a Data Subject Access Request."""
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    dsar_id = str(uuid.uuid4())

    # SEC-C4: canonical hash-chained trail.
    from warlock.db.audit import AuditTrail

    actor = f"api:{current_user.email}"
    AuditTrail(db).record(
        action="dsar_created",
        entity_type="dsar",
        entity_id=dsar_id,
        actor=actor,
        metadata={
            "subject_email": req.subject_email,
            "request_type": req.request_type,
            "status": "open",
            "description": req.description,
        },
    )

    return DSARResponse(
        id=dsar_id,
        subject_email=req.subject_email,
        request_type=req.request_type,
        status="open",
        created_at=_dt_str(now),
        description=req.description,
    )


# ---------------------------------------------------------------------------
# Routes — Breaches
# ---------------------------------------------------------------------------


@router.get("/privacy/breaches", response_model=PaginatedResponse)
def list_breaches(
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List privacy breach records."""
    limit, offset = pagination
    q = (
        db.query(AuditEntry)
        .filter(AuditEntry.entity_type == "privacy_breach")
        .order_by(AuditEntry.created_at.desc())
    )

    rows = q.all()

    items = []
    for r in rows:
        extra = r.extra or {}
        items.append(
            BreachResponse(
                id=r.entity_id,
                title=extra.get("title", ""),
                severity=extra.get("severity", "medium"),
                status=extra.get("status", "open"),
                reported_at=_dt_str(r.created_at),
                records_affected=extra.get("records_affected"),
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


# ---------------------------------------------------------------------------
# Routes — Transfers
# ---------------------------------------------------------------------------


@router.get("/privacy/transfers", response_model=PaginatedResponse)
def list_transfers(
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List cross-border data transfer records."""
    limit, offset = pagination
    q = (
        db.query(AuditEntry)
        .filter(AuditEntry.entity_type == "data_transfer")
        .order_by(AuditEntry.created_at.desc())
    )

    rows = q.all()

    items = []
    for r in rows:
        extra = r.extra or {}
        items.append(
            TransferResponse(
                id=r.entity_id,
                source_country=extra.get("source_country", ""),
                destination_country=extra.get("destination_country", ""),
                mechanism=extra.get("mechanism", ""),
                status=extra.get("status", "active"),
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


# ---------------------------------------------------------------------------
# Routes — ROPA (Records of Processing Activities)
# ---------------------------------------------------------------------------


@router.get("/privacy/ropa", response_model=PaginatedResponse)
def list_ropa(
    classification: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Records of Processing Activities from DataSilo inventory."""
    limit, offset = pagination
    q = (
        db.query(DataSilo)
        .filter(
            DataSilo.is_active == True  # noqa: E712
        )
        .order_by(DataSilo.name)
    )

    if classification:
        q = q.filter(DataSilo.data_classification == classification)

    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    items = [
        ROPAEntryResponse(
            id=r.id,
            name=r.name,
            silo_type=r.silo_type,
            provider=r.provider,
            data_classification=r.data_classification,
            contains_pii=r.contains_pii or False,
            contains_phi=r.contains_phi or False,
            owner=r.owner,
            applicable_frameworks=r.applicable_frameworks or [],
        ).model_dump()
        for r in rows
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )
