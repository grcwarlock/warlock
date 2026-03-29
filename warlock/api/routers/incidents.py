"""Incident management routes.

Incidents are stored as Issue records with severity-based classification.
Mirrors the warlock/cli/incidents_cmd.py patterns.
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
from warlock.db.models import AuditEntry, Issue, User

router = APIRouter()
log = logging.getLogger(__name__)

_VALID_STATUSES = [
    "open",
    "assigned",
    "in_progress",
    "remediated",
    "verified",
    "closed",
    "risk_accepted",
]
_VALID_SEVERITIES = ["critical", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class IncidentCreateRequest(BaseModel):
    title: str
    description: str | None = None
    severity: str = "medium"
    classification: str | None = None


class IncidentUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    assigned_to: str | None = None


class IncidentTransitionRequest(BaseModel):
    status: str
    notes: str | None = None


class IncidentResponse(BaseModel):
    id: str
    title: str
    description: str | None = None
    status: str
    severity: str
    classification: str | None = None
    assigned_to: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/incidents", response_model=PaginatedResponse)
def list_incidents(
    status: str | None = Query(None),
    severity: str | None = Query(None),
    pagination: tuple[int, int] = Depends(get_pagination),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List incidents (issues with incident classification) with pagination."""
    limit, offset = pagination
    q = db.query(Issue).order_by(Issue.created_at.desc())
    if status:
        q = q.filter(Issue.status == status)
    if severity:
        q = q.filter(Issue.priority == severity)

    total = q.count()
    rows = q.offset(offset).limit(limit).all()

    items = [
        IncidentResponse(
            id=r.id,
            title=r.title or "",
            description=r.description,
            status=r.status,
            severity=r.priority or "medium",
            classification=(r.tags[0] if r.tags else None),
            assigned_to=r.assigned_to,
            created_at=_dt_str(r.created_at),
            updated_at=_dt_str(r.updated_at),
        ).model_dump()
        for r in rows
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Get incident detail."""
    issue = db.query(Issue).filter(Issue.id == incident_id).first()
    if not issue:
        # Try prefix match
        issue = db.query(Issue).filter(Issue.id.startswith(incident_id)).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Incident not found")

    return IncidentResponse(
        id=issue.id,
        title=issue.title or "",
        description=issue.description,
        status=issue.status,
        severity=issue.priority or "medium",
        classification=(issue.tags[0] if issue.tags else None),
        assigned_to=issue.assigned_to,
        created_at=_dt_str(issue.created_at),
        updated_at=_dt_str(issue.updated_at),
    )


@router.post("/incidents", response_model=IncidentResponse, status_code=201)
def create_incident(
    req: IncidentCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a new incident."""
    if req.severity and req.severity not in _VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {req.severity}")

    now = datetime.now(timezone.utc)
    issue_id = str(uuid.uuid4())
    tags = [req.classification] if req.classification else []

    issue = Issue(
        id=issue_id,
        title=req.title,
        description=req.description,
        status="open",
        priority=req.severity or "medium",
        source="api",
        tags=tags,
        created_by=current_user.email,
        created_at=now,
        updated_at=now,
    )
    db.add(issue)

    # Audit entry
    last = db.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1
    actor = f"api:{current_user.email}"
    payload = f"{seq}:{prev_hash}:incident_created:{issue_id}:{actor}"
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action="incident_created",
        entity_type="issue",
        entity_id=issue_id,
        actor=actor,
        created_at=now,
    )
    db.add(audit)

    return IncidentResponse(
        id=issue.id,
        title=issue.title or "",
        description=issue.description,
        status=issue.status,
        severity=issue.priority or "medium",
        classification=(tags[0] if tags else None),
        assigned_to=issue.assigned_to,
        created_at=_dt_str(issue.created_at),
        updated_at=_dt_str(issue.updated_at),
    )


@router.patch(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
)
def update_incident(
    incident_id: str,
    req: IncidentUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Update incident fields."""
    issue = db.query(Issue).filter(Issue.id == incident_id).first()
    if not issue:
        issue = db.query(Issue).filter(Issue.id.startswith(incident_id)).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Incident not found")

    if req.title is not None:
        issue.title = req.title
    if req.description is not None:
        issue.description = req.description
    if req.severity is not None:
        if req.severity not in _VALID_SEVERITIES:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {req.severity}")
        issue.priority = req.severity
    if req.assigned_to is not None:
        issue.assigned_to = req.assigned_to
    issue.updated_at = datetime.now(timezone.utc)

    return IncidentResponse(
        id=issue.id,
        title=issue.title or "",
        description=issue.description,
        status=issue.status,
        severity=issue.priority or "medium",
        classification=(issue.tags[0] if issue.tags else None),
        assigned_to=issue.assigned_to,
        created_at=_dt_str(issue.created_at),
        updated_at=_dt_str(issue.updated_at),
    )


@router.post(
    "/incidents/{incident_id}/transition",
    response_model=IncidentResponse,
)
def transition_incident(
    incident_id: str,
    req: IncidentTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Transition incident status."""
    if req.status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status: {req.status}. Valid: {_VALID_STATUSES}",
        )

    issue = db.query(Issue).filter(Issue.id == incident_id).first()
    if not issue:
        issue = db.query(Issue).filter(Issue.id.startswith(incident_id)).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = datetime.now(timezone.utc)
    old_status = issue.status
    issue.status = req.status
    issue.updated_at = now

    if req.status in ("remediated",):
        issue.remediated_at = now
    if req.status in ("verified",):
        issue.verified_at = now
    if req.status in ("closed",):
        issue.closed_at = now

    # Audit entry for transition
    last = db.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
    prev_hash = last.entry_hash if last else "genesis"
    seq = (last.sequence + 1) if last else 1
    actor = f"api:{current_user.email}"
    payload = f"{seq}:{prev_hash}:incident_transition:{issue.id}:{old_status}->{req.status}:{actor}"
    entry_hash = hashlib.sha256(payload.encode()).hexdigest()

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        sequence=seq,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        action="incident_transition",
        entity_type="issue",
        entity_id=issue.id,
        actor=actor,
        extra={"from": old_status, "to": req.status, "notes": req.notes},
        created_at=now,
    )
    db.add(audit)

    return IncidentResponse(
        id=issue.id,
        title=issue.title or "",
        description=issue.description,
        status=issue.status,
        severity=issue.priority or "medium",
        classification=(issue.tags[0] if issue.tags else None),
        assigned_to=issue.assigned_to,
        created_at=_dt_str(issue.created_at),
        updated_at=_dt_str(issue.updated_at),
    )
