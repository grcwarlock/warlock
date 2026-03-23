"""Remediation workflow routes: 5-stage state machine (open -> assigned -> in_progress -> verification -> closed)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission, apply_framework_scope
from warlock.api.routers.schemas import PaginatedResponse, _dt_str, _parse_dt
from warlock.db.models import Remediation, User
from warlock.utils import ensure_aware

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State machine transitions
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS: dict[str, set[str]] = {
    "open": {"assigned"},
    "assigned": {"in_progress", "open"},  # allow reassign back to open
    "in_progress": {"verification", "assigned"},  # allow back to assigned
    "verification": {"closed", "in_progress"},  # reject sends back to in_progress
    "closed": set(),  # terminal state
}

_ALL_STATUSES = {"open", "assigned", "in_progress", "verification", "closed"}


def _check_transition(current: str, target: str) -> None:
    """Raise 409 if the transition is invalid."""
    allowed = _VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Invalid state transition: '{current}' -> '{target}'. "
                f"Allowed transitions from '{current}': {', '.join(sorted(allowed)) or 'none (terminal state)'}"
            ),
        )


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RemediationCreateRequest(BaseModel):
    title: str
    description: str | None = None
    finding_id: str | None = None
    control_result_id: str | None = None
    alert_id: str | None = None
    issue_id: str | None = None
    framework: str | None = None
    control_id: str | None = None
    remediation_plan: str | None = None
    remediation_steps: list[dict[str, Any]] | None = None
    due_date: str | None = None


class RemediationAssignRequest(BaseModel):
    assigned_to: str


class RemediationStartRequest(BaseModel):
    notes: str | None = None


class RemediationSubmitVerificationRequest(BaseModel):
    evidence: list[dict[str, Any]] | None = None
    notes: str | None = None


class RemediationVerifyRequest(BaseModel):
    verification_notes: str
    approved: bool = True


class RemediationResponse(BaseModel):
    id: str
    title: str
    description: str | None = None
    finding_id: str | None = None
    control_result_id: str | None = None
    alert_id: str | None = None
    issue_id: str | None = None
    framework: str | None = None
    control_id: str | None = None
    status: str
    assigned_to: str | None = None
    assigned_by: str | None = None
    assigned_at: str | None = None
    remediation_plan: str | None = None
    remediation_steps: list[dict[str, Any]] | None = None
    evidence: list[dict[str, Any]] | None = None
    verified_by: str | None = None
    verified_at: str | None = None
    verification_notes: str | None = None
    due_date: str | None = None
    closed_at: str | None = None
    created_at: str
    updated_at: str | None = None
    created_by: str | None = None

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _remediation_to_response(r: Remediation) -> RemediationResponse:
    return RemediationResponse(
        id=r.id,
        title=r.title,
        description=r.description,
        finding_id=r.finding_id,
        control_result_id=r.control_result_id,
        alert_id=r.alert_id,
        issue_id=r.issue_id,
        framework=r.framework,
        control_id=r.control_id,
        status=r.status,
        assigned_to=r.assigned_to,
        assigned_by=r.assigned_by,
        assigned_at=_dt_str(ensure_aware(r.assigned_at)),
        remediation_plan=r.remediation_plan,
        remediation_steps=r.remediation_steps,
        evidence=r.evidence,
        verified_by=r.verified_by,
        verified_at=_dt_str(ensure_aware(r.verified_at)),
        verification_notes=r.verification_notes,
        due_date=_dt_str(ensure_aware(r.due_date)),
        closed_at=_dt_str(ensure_aware(r.closed_at)),
        created_at=_dt_str(ensure_aware(r.created_at)) or "",
        updated_at=_dt_str(ensure_aware(r.updated_at)),
        created_by=r.created_by,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/remediations", response_model=PaginatedResponse)
def list_remediations(
    remediation_status: str | None = Query(None, alias="status"),
    assigned_to: str | None = Query(None),
    framework: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List remediations with optional filters."""
    query = db.query(Remediation)
    query = apply_framework_scope(query, Remediation, current_user)

    if remediation_status:
        if remediation_status not in _ALL_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status: {remediation_status}. Must be one of: {', '.join(sorted(_ALL_STATUSES))}",
            )
        query = query.filter(Remediation.status == remediation_status)
    if assigned_to:
        query = query.filter(Remediation.assigned_to == assigned_to)
    if framework:
        query = query.filter(Remediation.framework == framework)

    total = query.count()
    rows = query.order_by(Remediation.created_at.desc()).offset(offset).limit(limit).all()
    items = [_remediation_to_response(r) for r in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/remediations/{remediation_id}", response_model=RemediationResponse)
def get_remediation(
    remediation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Get a single remediation by ID."""
    r = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return _remediation_to_response(r)


@router.post("/remediations", response_model=RemediationResponse, status_code=201)
def create_remediation(
    body: RemediationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a new remediation."""
    r = Remediation(
        title=body.title,
        description=body.description,
        finding_id=body.finding_id,
        control_result_id=body.control_result_id,
        alert_id=body.alert_id,
        issue_id=body.issue_id,
        framework=body.framework,
        control_id=body.control_id,
        remediation_plan=body.remediation_plan,
        remediation_steps=body.remediation_steps or [],
        due_date=_parse_dt(body.due_date) if body.due_date else None,
        status="open",
        created_by=current_user.email,
    )
    db.add(r)
    db.flush()
    log.info("Remediation created: %s by %s", r.id, current_user.email)
    return _remediation_to_response(r)


@router.patch("/remediations/{remediation_id}/assign", response_model=RemediationResponse)
def assign_remediation(
    remediation_id: str,
    body: RemediationAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Assign a remediation to a user (open -> assigned)."""
    r = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Remediation not found")

    _check_transition(r.status, "assigned")

    now = datetime.now(timezone.utc)
    r.status = "assigned"
    r.assigned_to = body.assigned_to
    r.assigned_by = current_user.email
    r.assigned_at = now
    db.flush()
    log.info(
        "Remediation %s assigned to %s by %s", remediation_id, body.assigned_to, current_user.email
    )
    return _remediation_to_response(r)


@router.patch("/remediations/{remediation_id}/start", response_model=RemediationResponse)
def start_remediation(
    remediation_id: str,
    body: RemediationStartRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Start work on a remediation (assigned -> in_progress)."""
    r = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Remediation not found")

    _check_transition(r.status, "in_progress")

    r.status = "in_progress"
    db.flush()
    log.info("Remediation %s started by %s", remediation_id, current_user.email)
    return _remediation_to_response(r)


@router.patch(
    "/remediations/{remediation_id}/submit-verification",
    response_model=RemediationResponse,
)
def submit_verification(
    remediation_id: str,
    body: RemediationSubmitVerificationRequest | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Submit remediation for verification (in_progress -> verification)."""
    r = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Remediation not found")

    _check_transition(r.status, "verification")

    if body and body.evidence:
        existing = r.evidence or []
        r.evidence = existing + body.evidence
    if body and body.notes:
        r.verification_notes = body.notes
    r.status = "verification"
    db.flush()
    log.info("Remediation %s submitted for verification by %s", remediation_id, current_user.email)
    return _remediation_to_response(r)


@router.patch("/remediations/{remediation_id}/verify", response_model=RemediationResponse)
def verify_remediation(
    remediation_id: str,
    body: RemediationVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Verify and close a remediation (verification -> closed), or reject back to in_progress."""
    r = db.query(Remediation).filter(Remediation.id == remediation_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Remediation not found")

    if body.approved:
        _check_transition(r.status, "closed")
        now = datetime.now(timezone.utc)
        r.status = "closed"
        r.verified_by = current_user.email
        r.verified_at = now
        r.verification_notes = body.verification_notes
        r.closed_at = now
        log.info("Remediation %s verified and closed by %s", remediation_id, current_user.email)
    else:
        _check_transition(r.status, "in_progress")
        r.status = "in_progress"
        r.verification_notes = body.verification_notes
        log.info(
            "Remediation %s rejected back to in_progress by %s", remediation_id, current_user.email
        )

    db.flush()
    return _remediation_to_response(r)
