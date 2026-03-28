"""Evidence submission portal API (GAP-054).

Provides endpoints for users to submit evidence against controls and
to view pending evidence requests and their own submissions.

Uses the ``EvidenceRequest`` model from ``warlock.db.models``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.deps import get_current_user, get_db, get_pagination, AuthContext
from warlock.db.models import EvidenceRequest
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

router = APIRouter(prefix="/evidence-portal", tags=["Evidence Portal"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class EvidenceSubmitBody(BaseModel):
    control_id: str = Field(..., min_length=1, max_length=50)
    framework: str = Field(..., min_length=1, max_length=50)
    description: str = Field(..., min_length=1, max_length=4000)
    file_hash: str = Field(
        default="",
        max_length=128,
        description="SHA-256 hash of the uploaded evidence file",
    )


class EvidenceSubmitResponse(BaseModel):
    evidence_id: str
    status: str
    message: str


class EvidenceRequestItem(BaseModel):
    id: str
    framework: str | None
    control_id: str | None
    description: str
    status: str
    created_at: str
    fulfilled_at: str | None = None


class EvidenceSubmissionItem(BaseModel):
    id: str
    framework: str | None
    control_id: str | None
    description: str
    status: str
    created_at: str
    fulfillment_notes: str | None = None


# ---------------------------------------------------------------------------
# POST /evidence-portal/submit
# ---------------------------------------------------------------------------


@router.post("/submit", response_model=EvidenceSubmitResponse, status_code=201)
def submit_evidence(
    body: EvidenceSubmitBody,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_user),
) -> EvidenceSubmitResponse:
    """Submit evidence for a control.

    Creates a new EvidenceRequest record in ``fulfilled`` status with the
    submitter's information attached.
    """
    user = auth.user

    er = EvidenceRequest(
        # EvidenceRequest requires engagement_id and auditor_id which are FK
        # constraints.  For self-service submissions we set the description
        # and mark as fulfilled directly.  We need valid FKs -- use a
        # sentinel approach: store metadata in fulfillment_notes and
        # evidence_ids JSON field.
        engagement_id=_get_or_create_self_service_engagement(db),
        auditor_id=_get_or_create_self_service_auditor(db, user.email, user.username),
        framework=body.framework,
        control_id=body.control_id,
        description=body.description,
        status="fulfilled",
        fulfilled_by=user.username or user.email,
        fulfilled_at=datetime.now(timezone.utc),
        fulfillment_notes=f"Self-service submission. File hash: {body.file_hash}"
        if body.file_hash
        else "Self-service submission.",
        evidence_ids=[
            {
                "file_hash": body.file_hash,
                "submitted_by": user.email,
                "submitted_at": datetime.now(timezone.utc).isoformat(),
            }
        ],
    )
    db.add(er)
    db.flush()

    log.info(
        "Evidence submitted: id=%s control=%s framework=%s by=%s",
        er.id,
        body.control_id,
        body.framework,
        user.email,
    )

    return EvidenceSubmitResponse(
        evidence_id=er.id,
        status="fulfilled",
        message="Evidence submitted successfully.",
    )


# ---------------------------------------------------------------------------
# GET /evidence-portal/requests
# ---------------------------------------------------------------------------


@router.get("/requests", response_model=list[EvidenceRequestItem])
def list_evidence_requests(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_user),
    pagination=Depends(get_pagination),
) -> list[EvidenceRequestItem]:
    """List pending evidence requests for the current user.

    Returns EvidenceRequest records that have not yet been fulfilled,
    filtered to those assigned to the current user's auditor record
    (if one exists) or all pending requests for admin users.
    """
    query = (
        db.query(EvidenceRequest)
        .filter(EvidenceRequest.status.in_(["requested", "in_progress"]))
        .order_by(EvidenceRequest.created_at.desc())
    )

    # Non-admin users only see requests assigned to their auditor ID
    if "manage_users" not in auth.effective_permissions:
        from warlock.db.models import ExternalAuditor

        auditor = db.query(ExternalAuditor).filter(ExternalAuditor.email == auth.user.email).first()
        if auditor:
            query = query.filter(EvidenceRequest.auditor_id == auditor.id)
        else:
            return []

    items = query.offset(pagination.offset).limit(pagination.limit).all()

    results: list[EvidenceRequestItem] = []
    for er in items:
        created_at = ensure_aware(er.created_at).isoformat()
        fulfilled_at = None
        if er.fulfilled_at:
            fulfilled_at = ensure_aware(er.fulfilled_at).isoformat()
        results.append(
            EvidenceRequestItem(
                id=er.id,
                framework=er.framework,
                control_id=er.control_id,
                description=er.description,
                status=er.status,
                created_at=created_at,
                fulfilled_at=fulfilled_at,
            )
        )

    return results


# ---------------------------------------------------------------------------
# GET /evidence-portal/my-submissions
# ---------------------------------------------------------------------------


@router.get("/my-submissions", response_model=list[EvidenceSubmissionItem])
def my_submissions(
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_user),
    pagination=Depends(get_pagination),
) -> list[EvidenceSubmissionItem]:
    """List evidence submissions made by the current user."""
    user = auth.user

    query = (
        db.query(EvidenceRequest)
        .filter(
            EvidenceRequest.fulfilled_by.in_([user.email, user.username]),
        )
        .order_by(EvidenceRequest.created_at.desc())
    )

    items = query.offset(pagination.offset).limit(pagination.limit).all()

    results: list[EvidenceSubmissionItem] = []
    for er in items:
        created_at = ensure_aware(er.created_at).isoformat()
        results.append(
            EvidenceSubmissionItem(
                id=er.id,
                framework=er.framework,
                control_id=er.control_id,
                description=er.description,
                status=er.status,
                created_at=created_at,
                fulfillment_notes=er.fulfillment_notes,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Helpers — self-service sentinel records
# ---------------------------------------------------------------------------


def _get_or_create_self_service_engagement(db: Session) -> str:
    """Return the ID of a sentinel AuditEngagement for self-service evidence."""
    from warlock.db.models import AuditEngagement

    sentinel_name = "__self_service_evidence__"
    eng = db.query(AuditEngagement).filter(AuditEngagement.name == sentinel_name).first()
    if eng:
        return eng.id

    eng = AuditEngagement(
        name=sentinel_name,
        framework="all",
        status="active",
    )
    db.add(eng)
    db.flush()
    return eng.id


def _get_or_create_self_service_auditor(db: Session, email: str, name: str) -> str:
    """Return the ID of an ExternalAuditor for the given user email."""
    from warlock.db.models import ExternalAuditor

    auditor = db.query(ExternalAuditor).filter(ExternalAuditor.email == email).first()
    if auditor:
        return auditor.id

    auditor = ExternalAuditor(
        email=email,
        name=name or email,
    )
    db.add(auditor)
    db.flush()
    return auditor.id
