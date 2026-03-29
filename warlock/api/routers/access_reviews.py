"""Access review campaign routes.

Campaigns are stored as AuditEntry records with action='access_review_campaign',
mirroring warlock/cli/access_review_cmd.py.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, get_pagination, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import AuditEntry, User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CampaignCreateRequest(BaseModel):
    scope: str
    reviewer: str
    deadline: str
    notes: str | None = None


class CampaignResponse(BaseModel):
    id: str
    scope: str
    reviewer: str
    deadline: str | None = None
    status: str
    certified_count: int
    total_count: int
    created_at: str | None = None


class ReviewItemResponse(BaseModel):
    user_email: str
    decision: str | None = None
    decided_by: str | None = None
    decided_at: str | None = None


class DecisionRequest(BaseModel):
    decision: str  # approve, revoke


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_campaign(db: Session, campaign_id: str) -> AuditEntry | None:
    row = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.action == "access_review_campaign",
            AuditEntry.entity_type == "access_review",
            AuditEntry.entity_id.startswith(campaign_id),
        )
        .first()
    )
    return row


def _campaign_status(entry: AuditEntry) -> str:
    extra = entry.extra or {}
    stored = extra.get("status", "active")
    if stored in ("completed", "cancelled"):
        return stored
    deadline_str = extra.get("deadline")
    if deadline_str:
        try:
            dl = datetime.fromisoformat(deadline_str)
            if dl.tzinfo is None:
                dl = dl.replace(tzinfo=timezone.utc)
            if dl < datetime.now(timezone.utc):
                return "overdue"
        except ValueError:
            pass
    return "active"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/access-reviews", response_model=PaginatedResponse)
def list_campaigns(
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List access review campaigns."""
    limit, offset = pagination
    q = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.action == "access_review_campaign",
            AuditEntry.entity_type == "access_review",
        )
        .order_by(AuditEntry.created_at.desc())
    )

    rows = q.all()

    items = []
    for r in rows:
        extra = r.extra or {}
        certs = extra.get("certifications", [])
        total_users = extra.get("total_users", len(certs))
        items.append(
            CampaignResponse(
                id=r.entity_id,
                scope=extra.get("scope", ""),
                reviewer=extra.get("reviewer", ""),
                deadline=extra.get("deadline"),
                status=_campaign_status(r),
                certified_count=len(certs),
                total_count=total_users,
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


@router.post(
    "/access-reviews",
    response_model=CampaignResponse,
    status_code=201,
)
def create_campaign(
    req: CampaignCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a new access review campaign."""
    now = datetime.now(timezone.utc)
    campaign_id = str(uuid.uuid4())

    last = db.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1
    actor = f"api:{current_user.email}"
    payload = f"{seq}:{prev_hash}:access_review_campaign:{campaign_id}:{actor}"
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action="access_review_campaign",
        entity_type="access_review",
        entity_id=campaign_id,
        actor=actor,
        extra={
            "scope": req.scope,
            "reviewer": req.reviewer,
            "deadline": req.deadline,
            "status": "active",
            "certifications": [],
            "notes": req.notes,
        },
        created_at=now,
    )
    db.add(audit)

    return CampaignResponse(
        id=campaign_id,
        scope=req.scope,
        reviewer=req.reviewer,
        deadline=req.deadline,
        status="active",
        certified_count=0,
        total_count=0,
        created_at=_dt_str(now),
    )


@router.get(
    "/access-reviews/{campaign_id}/items",
    response_model=list[ReviewItemResponse],
)
def list_review_items(
    campaign_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List review items (certifications) for a campaign."""
    entry = _load_campaign(db, campaign_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Campaign not found")

    extra = entry.extra or {}
    certs = extra.get("certifications", [])

    return [
        ReviewItemResponse(
            user_email=c.get("user_email", ""),
            decision=c.get("decision"),
            decided_by=c.get("decided_by"),
            decided_at=c.get("decided_at"),
        )
        for c in certs
    ]


@router.post(
    "/access-reviews/{campaign_id}/items/{item_id}/decide",
    response_model=ReviewItemResponse,
)
def decide_review_item(
    campaign_id: str,
    item_id: str,
    req: DecisionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Approve or revoke an access review item."""
    if req.decision not in ("approve", "revoke"):
        raise HTTPException(status_code=400, detail="Decision must be 'approve' or 'revoke'")

    entry = _load_campaign(db, campaign_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Campaign not found")

    now = datetime.now(timezone.utc)
    extra = entry.extra or {}
    certs = extra.get("certifications", [])

    # Record the decision
    cert_record = {
        "user_email": item_id,
        "decision": req.decision,
        "decided_by": current_user.email,
        "decided_at": now.isoformat(),
    }
    certs.append(cert_record)
    extra["certifications"] = certs
    entry.extra = extra
    # Force SQLAlchemy to detect the change
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(entry, "extra")

    return ReviewItemResponse(
        user_email=item_id,
        decision=req.decision,
        decided_by=current_user.email,
        decided_at=now.isoformat(),
    )
