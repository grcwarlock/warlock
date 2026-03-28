"""Trust portal API routes for auditor self-service access (GAP-047).

Provides endpoints for external auditors to request access to compliance
documentation, check their request status, and (once approved) list and
download trust documents.

Authentication is lightweight: the requester's email is used to look up
an approved ``TrustAccessRequest``.
"""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.deps import get_db
from warlock.db.models import TrustAccessRequest, TrustDocument
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

router = APIRouter(prefix="/trust-portal", tags=["Trust Portal (Self-Service)"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AccessRequestBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    email: str = Field(..., min_length=3, max_length=255)
    organization: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(default="", max_length=2000)


class AccessRequestResponse(BaseModel):
    request_id: str
    status: str
    message: str


class AccessStatusResponse(BaseModel):
    request_id: str
    status: str
    submitted_at: str
    reviewed_at: str | None = None


class TrustDocumentItem(BaseModel):
    id: str
    title: str
    description: str
    classification_tier: str
    content_type: str
    file_size_bytes: int
    uploaded_at: str


class TrustDocumentDownload(BaseModel):
    document_id: str
    title: str
    download_url: str
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_email(email: str) -> str:
    """Validate and return a normalised email, or raise 400."""
    email = email.strip().lower()
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise HTTPException(status_code=400, detail="Invalid email address.")
    return email


def _get_approved_request(email: str, db: Session) -> TrustAccessRequest:
    """Return the most recent approved TrustAccessRequest for *email*, or 403."""
    req = (
        db.query(TrustAccessRequest)
        .filter(
            TrustAccessRequest.contact_email == email,
            TrustAccessRequest.status == "approved",
        )
        .order_by(TrustAccessRequest.created_at.desc())
        .first()
    )
    if not req:
        raise HTTPException(
            status_code=403,
            detail="No approved access request found for this email.",
        )
    return req


# ---------------------------------------------------------------------------
# POST /trust-portal/request-access
# ---------------------------------------------------------------------------


@router.post("/request-access", response_model=AccessRequestResponse, status_code=201)
def request_access(
    body: AccessRequestBody,
    db: Session = Depends(get_db),
) -> AccessRequestResponse:
    """Submit an access request for compliance documentation."""
    email = _validate_email(body.email)

    req = TrustAccessRequest(
        company_name=body.organization,
        contact_name=body.name,
        contact_email=email,
        reason=body.reason,
        status="pending",
    )
    db.add(req)
    db.flush()

    log.info(
        "Trust portal access request created: id=%s email=%s org=%s",
        req.id,
        email,
        body.organization,
    )

    return AccessRequestResponse(
        request_id=req.id,
        status="pending",
        message="Access request submitted. You will be notified once reviewed.",
    )


# ---------------------------------------------------------------------------
# GET /trust-portal/status
# ---------------------------------------------------------------------------


@router.get("/status", response_model=AccessStatusResponse)
def check_status(
    email: str = Query(..., description="Email used when requesting access"),
    db: Session = Depends(get_db),
) -> AccessStatusResponse:
    """Check the status of an access request by email."""
    email = _validate_email(email)

    req = (
        db.query(TrustAccessRequest)
        .filter(TrustAccessRequest.contact_email == email)
        .order_by(TrustAccessRequest.created_at.desc())
        .first()
    )
    if not req:
        raise HTTPException(
            status_code=404,
            detail="No access request found for this email.",
        )

    submitted_at = ensure_aware(req.created_at).isoformat()
    reviewed_at = None
    if req.reviewed_at:
        reviewed_at = ensure_aware(req.reviewed_at).isoformat()

    return AccessStatusResponse(
        request_id=req.id,
        status=req.status,
        submitted_at=submitted_at,
        reviewed_at=reviewed_at,
    )


# ---------------------------------------------------------------------------
# GET /trust-portal/documents
# ---------------------------------------------------------------------------


@router.get("/documents", response_model=list[TrustDocumentItem])
def list_documents(
    email: str = Query(..., description="Approved requester email"),
    db: Session = Depends(get_db),
) -> list[TrustDocumentItem]:
    """List available trust documents (requires approved access)."""
    email = _validate_email(email)
    _get_approved_request(email, db)  # raises 403 if not approved

    docs = (
        db.query(TrustDocument)
        .filter(
            TrustDocument.is_active == True,  # noqa: E712
            TrustDocument.classification_tier.in_(["public", "nda"]),
        )
        .order_by(TrustDocument.uploaded_at.desc())
        .all()
    )

    results: list[TrustDocumentItem] = []
    for doc in docs:
        uploaded_at = ensure_aware(doc.uploaded_at).isoformat()
        results.append(
            TrustDocumentItem(
                id=doc.id,
                title=doc.title,
                description=doc.description or "",
                classification_tier=doc.classification_tier,
                content_type=doc.content_type or "application/octet-stream",
                file_size_bytes=doc.file_size_bytes or 0,
                uploaded_at=uploaded_at,
            )
        )

    return results


# ---------------------------------------------------------------------------
# GET /trust-portal/documents/{document_id}/download
# ---------------------------------------------------------------------------


@router.get(
    "/documents/{document_id}/download",
    response_model=TrustDocumentDownload,
)
def download_document(
    document_id: str,
    email: str = Query(..., description="Approved requester email"),
    db: Session = Depends(get_db),
) -> TrustDocumentDownload:
    """Get download info for a specific trust document."""
    email = _validate_email(email)
    _get_approved_request(email, db)

    doc = (
        db.query(TrustDocument)
        .filter(
            TrustDocument.id == document_id,
            TrustDocument.is_active == True,  # noqa: E712
        )
        .first()
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    # For NDA/contract docs, require approved access (already checked above)
    # Build a redirect to the existing signed-URL endpoint on the trust portal
    download_url = f"/trust/documents/{document_id}/download"

    log.info(
        "Trust portal document download: doc=%s email=%s",
        document_id,
        email,
    )

    return TrustDocumentDownload(
        document_id=document_id,
        title=doc.title,
        download_url=download_url,
        message="Use the download_url to retrieve the document.",
    )
