"""Public trust portal endpoints. No authentication required (public tier).

Exposes high-level compliance posture without sensitive details, plus
NDA-gated document management for #45: SOC 2 report portal.

Document endpoints:
- POST /api/v1/trust/documents            -- upload a compliance document
- GET  /api/v1/trust/documents            -- list docs for caller's access tier
- GET  /api/v1/trust/documents/{id}/download -- time-limited download URL
- GET  /api/v1/trust/access-requests/{id}/documents -- post-NDA doc list
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.api.deps import get_current_user, get_db, require_permission
from warlock.db.models import (
    AuditEngagement,
    ControlResult,
    PostureSnapshot,
    TrustAccessRequest,
    TrustDocument,
)


# ---------------------------------------------------------------------------
# Download token signing — HMAC-SHA256, 1-hour TTL
# ---------------------------------------------------------------------------
# Load from settings — refuse hardcoded default in production
def _get_download_secret() -> str:
    from warlock.config import get_settings

    s = get_settings()
    secret = getattr(s, "trust_portal_secret", "") or ""
    if not secret:
        if getattr(s, "env", "development") == "production":
            raise RuntimeError("WLK_TRUST_PORTAL_SECRET must be set in production")
        secret = "wlk-trust-portal-dev-only-secret"
    return secret


log = logging.getLogger(__name__)

router = APIRouter(prefix="/trust", tags=["Trust Portal"])


def _bin_control_count(count: int) -> str:
    """S-7: Bin exact control counts into ranges to avoid leaking precise topology."""
    if count >= 200:
        return "200+"
    elif count >= 100:
        return "100+"
    elif count >= 50:
        return "50-99"
    elif count >= 10:
        return "10-49"
    elif count >= 1:
        return "1-9"
    return "0"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class FrameworkStatus(BaseModel):
    framework: str
    posture_rating: str  # "Strong", "Moderate", "Needs Improvement"
    total_controls: str  # S-7: Binned range string, not exact count
    compliance_rate_band: str  # "90-100%", "70-89%", "50-69%", "Below 50%"


class TrustStatusResponse(BaseModel):
    overall_rating: str  # "Strong", "Moderate", "Needs Improvement"
    frameworks: list[FrameworkStatus]
    last_assessment: str | None
    assessed_frameworks_count: int
    timestamp: str


class CertificationResponse(BaseModel):
    framework: str
    status: str
    auditor_firm: str | None
    period_start: str | None
    period_end: str | None
    name: str


class SecurityUpdateResponse(BaseModel):
    date: str
    category: str
    description: str


class AccessRequestFormResponse(BaseModel):
    fields: list[dict[str, Any]]
    instructions: str


class AccessRequestSubmitRequest(BaseModel):
    company_name: str
    contact_name: str
    contact_email: str
    document_types: list[str] = Field(default_factory=list)
    reason: str = ""
    nda_accepted: bool = False


class AccessRequestSubmitResponse(BaseModel):
    request_id: str
    message: str
    status: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status", response_model=TrustStatusResponse)
async def trust_status(db: Session = Depends(get_db)):
    """Public compliance status summary.

    Returns: frameworks, overall posture score, last assessment date.
    """
    # Get latest posture snapshots per framework
    latest_date = db.query(func.max(PostureSnapshot.snapshot_date)).scalar()

    frameworks: list[FrameworkStatus] = []
    overall_scores: list[float] = []

    if latest_date:
        snapshots = (
            db.query(PostureSnapshot).filter(PostureSnapshot.snapshot_date == latest_date).all()
        )

        # Aggregate by framework
        fw_data: dict[str, dict[str, Any]] = {}
        for snap in snapshots:
            fw = snap.framework
            if fw not in fw_data:
                fw_data[fw] = {
                    "scores": [],
                    "total": 0,
                    "compliant": 0,
                    "non_compliant": 0,
                    "partial": 0,
                }
            fw_data[fw]["scores"].append(snap.posture_score)
            fw_data[fw]["total"] += 1
            if snap.status == "compliant":
                fw_data[fw]["compliant"] += 1
            elif snap.status == "non_compliant":
                fw_data[fw]["non_compliant"] += 1
            elif snap.status == "partial":
                fw_data[fw]["partial"] += 1

        for fw, data in sorted(fw_data.items()):
            avg_score = sum(data["scores"]) / len(data["scores"]) if data["scores"] else 0
            compliance_rate = (data["compliant"] / data["total"] * 100) if data["total"] else 0
            overall_scores.append(avg_score)

            # Bin scores for public consumption — no exact counts
            if compliance_rate >= 90:
                rating = "Strong"
                band = "90-100%"
            elif compliance_rate >= 70:
                rating = "Moderate"
                band = "70-89%"
            elif compliance_rate >= 50:
                rating = "Needs Improvement"
                band = "50-69%"
            else:
                rating = "Needs Improvement"
                band = "Below 50%"

            frameworks.append(
                FrameworkStatus(
                    framework=fw,
                    posture_rating=rating,
                    total_controls=_bin_control_count(data["total"]),
                    compliance_rate_band=band,
                )
            )

    overall = round(sum(overall_scores) / len(overall_scores), 1) if overall_scores else 0

    # Last assessment
    last_result = db.query(ControlResult).order_by(ControlResult.assessed_at.desc()).first()
    last_assessment = None
    if last_result and last_result.assessed_at:
        dt = last_result.assessed_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        last_assessment = dt.isoformat()

    # Bin overall score for public view
    if overall >= 80:
        overall_rating = "Strong"
    elif overall >= 60:
        overall_rating = "Moderate"
    else:
        overall_rating = "Needs Improvement"

    return TrustStatusResponse(
        overall_rating=overall_rating,
        frameworks=frameworks,
        last_assessment=last_assessment,
        assessed_frameworks_count=len(frameworks),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/certifications", response_model=list[CertificationResponse])
async def certifications(db: Session = Depends(get_db)):
    """List active certifications/attestations (SOC 2, ISO 27001, etc.)."""
    engagements = (
        db.query(AuditEngagement)
        .filter(AuditEngagement.status.in_(["active", "completed"]))
        .order_by(AuditEngagement.period_end.desc())
        .all()
    )

    results = []
    for eng in engagements:
        period_start = None
        period_end = None
        if eng.period_start:
            dt = eng.period_start
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            period_start = dt.isoformat()
        if eng.period_end:
            dt = eng.period_end
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            period_end = dt.isoformat()

        results.append(
            CertificationResponse(
                framework=eng.framework,
                status=eng.status,
                auditor_firm=eng.auditor_firm,
                period_start=period_start,
                period_end=period_end,
                name=eng.name,
            )
        )

    return results


@router.get("/security-updates", response_model=list[SecurityUpdateResponse])
async def security_updates(db: Session = Depends(get_db)):
    """Recent security improvements and compliance milestones.

    Derived from recent completed engagements and posture improvements.
    """
    updates: list[SecurityUpdateResponse] = []

    # Recent completed engagements
    recent_engagements = (
        db.query(AuditEngagement)
        .filter(AuditEngagement.status == "completed")
        .order_by(AuditEngagement.completed_at.desc())
        .limit(10)
        .all()
    )

    for eng in recent_engagements:
        completed_dt = eng.completed_at or eng.created_at
        if completed_dt:
            if completed_dt.tzinfo is None:
                completed_dt = completed_dt.replace(tzinfo=timezone.utc)
            updates.append(
                SecurityUpdateResponse(
                    date=completed_dt.isoformat(),
                    category="certification",
                    description=f"Completed {eng.name} ({eng.framework})",
                )
            )

    # Sort by date descending
    updates.sort(key=lambda u: u.date, reverse=True)
    return updates[:20]


@router.get("/request-access", response_model=AccessRequestFormResponse)
async def request_access_form():
    """Return form fields for requesting detailed compliance docs."""
    return AccessRequestFormResponse(
        fields=[
            {"name": "company_name", "type": "text", "required": True, "label": "Company Name"},
            {"name": "contact_name", "type": "text", "required": True, "label": "Contact Name"},
            {"name": "contact_email", "type": "email", "required": True, "label": "Contact Email"},
            {
                "name": "document_types",
                "type": "multiselect",
                "required": False,
                "label": "Requested Documents",
                "options": [
                    "SOC 2 Type II Report",
                    "ISO 27001 Certificate",
                    "ISO 27701 Certificate",
                    "Penetration Test Summary",
                    "Security Whitepaper",
                    "Data Processing Agreement",
                    "SIG Questionnaire",
                    "CAIQ",
                ],
            },
            {"name": "reason", "type": "textarea", "required": False, "label": "Reason / Notes"},
            {
                "name": "nda_accepted",
                "type": "checkbox",
                "required": True,
                "label": "I agree to NDA terms for access to compliance documentation",
            },
        ],
        instructions=(
            "Submit this form to request access to detailed compliance documentation. "
            "An NDA may be required before documents are shared. "
            "You will receive a response within 2 business days."
        ),
    )


@router.post("/request-access", response_model=AccessRequestSubmitResponse)
async def submit_access_request(
    body: AccessRequestSubmitRequest,
    db: Session = Depends(get_db),
):
    """Submit a request for compliance documents (NDA required)."""
    if not body.nda_accepted:
        raise HTTPException(
            status_code=400,
            detail="NDA acceptance is required to request compliance documents.",
        )

    # S-17: Proper email validation with regex
    if not body.contact_email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", body.contact_email):
        raise HTTPException(status_code=400, detail="A valid contact email is required.")

    req = TrustAccessRequest(
        company_name=body.company_name,
        contact_name=body.contact_name,
        contact_email=body.contact_email,
        document_types=body.document_types,
        reason=body.reason,
        nda_accepted=body.nda_accepted,
        status="pending",
    )
    db.add(req)
    db.flush()

    log.info(
        "Trust portal access request from %s (%s): %s", body.contact_name, body.company_name, req.id
    )

    return AccessRequestSubmitResponse(
        request_id=req.id,
        message="Your request has been submitted. You will be contacted within 2 business days.",
        status="pending",
    )


# ---------------------------------------------------------------------------
# #45: SOC 2 Report Portal — NDA-gated document access
# ---------------------------------------------------------------------------

_VALID_TIERS = {"public", "nda", "contract"}
_DOWNLOAD_URL_TTL = 3600  # 1 hour


def _sign_download_token(doc_id: str, expires_at: int) -> str:
    """Return an HMAC-SHA256 token for a time-limited download URL."""
    msg = f"{doc_id}:{expires_at}"
    return hmac.new(  # type: ignore[attr-defined]  # stdlib alias
        _get_download_secret().encode(),
        msg.encode(),
        hashlib.sha256,
    ).hexdigest()


def _verify_download_token(doc_id: str, expires_at: int, token: str) -> bool:
    """Verify a previously signed download token, checking TTL."""
    if time.time() > expires_at:
        return False
    expected = _sign_download_token(doc_id, expires_at)
    return hmac.compare_digest(expected, token)


class TrustDocumentResponse(BaseModel):
    id: str
    title: str
    description: str
    classification_tier: str
    content_type: str
    file_size_bytes: int
    uploaded_by: str
    uploaded_at: str

    model_config = {"from_attributes": True}


class TrustDocumentUploadResponse(BaseModel):
    id: str
    title: str
    classification_tier: str
    message: str


class TrustDocumentDownloadResponse(BaseModel):
    document_id: str
    title: str
    download_url: str
    expires_at: str


def _doc_to_response(doc: TrustDocument) -> TrustDocumentResponse:
    dt = doc.uploaded_at
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return TrustDocumentResponse(
        id=doc.id,
        title=doc.title,
        description=doc.description or "",
        classification_tier=doc.classification_tier,
        content_type=doc.content_type or "application/octet-stream",
        file_size_bytes=doc.file_size_bytes or 0,
        uploaded_by=doc.uploaded_by,
        uploaded_at=dt.isoformat(),
    )


@router.post("/documents", response_model=TrustDocumentUploadResponse, status_code=201)
async def upload_trust_document(
    title: str = Form(..., description="Document title (e.g. 'SOC 2 Type II Report 2025')"),
    classification_tier: str = Form(..., description="public | nda | contract"),
    description: str = Form(default=""),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("manage_users")),
):
    """Upload a compliance document (SOC 2, pen test summary, etc.).

    Requires manage_users permission (admin/owner only).
    File is stored on the server filesystem under a deterministic path.
    """
    if classification_tier not in _VALID_TIERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid classification_tier '{classification_tier}'. Must be one of: {sorted(_VALID_TIERS)}",
        )

    # Validate file type
    _ALLOWED_TYPES = {"application/pdf", "image/png", "image/jpeg", "text/csv", "application/json"}
    if file.content_type and file.content_type not in _ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"File type '{file.content_type}' not allowed. Allowed: {sorted(_ALLOWED_TYPES)}",
        )

    # Sanitize title and build a storage key
    safe_title = re.sub(r"[^\w\s\-.]", "", title)[:120].strip().replace(" ", "_")
    if not safe_title:
        raise HTTPException(
            status_code=400, detail="Title must contain at least one alphanumeric character."
        )

    import os
    import uuid

    doc_id = str(uuid.uuid4())

    # Read with size limit (50MB)
    _MAX_UPLOAD_SIZE = 50 * 1024 * 1024
    content = await file.read(_MAX_UPLOAD_SIZE + 1)
    if len(content) > _MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds maximum upload size of 50MB")
    file_size = len(content)

    # Store under exports/trust_documents/<tier>/<id>_<safe_title>
    store_dir = os.path.join("exports", "trust_documents", classification_tier)
    os.makedirs(store_dir, exist_ok=True)
    filename = f"{doc_id}_{safe_title}"
    file_path = os.path.join(store_dir, filename)
    with open(file_path, "wb") as fh:
        fh.write(content)

    doc = TrustDocument(
        id=doc_id,
        title=title,
        description=description,
        classification_tier=classification_tier,
        file_path=file_path,
        content_type=file.content_type or "application/octet-stream",
        file_size_bytes=file_size,
        uploaded_by=current_user.email,
        is_active=True,
    )
    db.add(doc)
    db.flush()

    log.info(
        "Trust document uploaded: %s tier=%s size=%d bytes by %s",
        doc.id,
        classification_tier,
        file_size,
        current_user.email,
    )

    return TrustDocumentUploadResponse(
        id=doc.id,
        title=doc.title,
        classification_tier=doc.classification_tier,
        message="Document uploaded successfully.",
    )


@router.get("/documents", response_model=list[TrustDocumentResponse])
async def list_trust_documents(
    tier: str | None = None,
    db: Session = Depends(get_db),
):
    """List available compliance documents.

    Public tier is unauthenticated. NDA and contract tiers require authentication.
    """
    allowed_tier = tier or "public"
    # Enforce auth for non-public tiers
    if allowed_tier in ("nda", "contract"):
        # Non-public tiers should not be browseable without auth
        raise HTTPException(
            status_code=401,
            detail="Authentication required for NDA and contract tier documents. Use the access-request flow.",
        )
    if allowed_tier not in _VALID_TIERS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tier '{allowed_tier}'. Must be one of: {sorted(_VALID_TIERS)}",
        )

    # For unauthenticated browsing, only expose public documents
    query = (
        db.query(TrustDocument)
        .filter(
            TrustDocument.is_active == True,  # noqa: E712
            TrustDocument.classification_tier == allowed_tier,
        )
        .order_by(TrustDocument.uploaded_at.desc())
    )

    docs = query.all()
    return [_doc_to_response(d) for d in docs]


@router.get("/documents/{document_id}/download", response_model=TrustDocumentDownloadResponse)
async def get_document_download_url(
    document_id: str,
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None),
):
    """Generate a time-limited (1 hour) signed download URL for a document.

    The generated URL is signed with HMAC-SHA256 and encodes an expiry
    timestamp. The actual file serving is handled by the /download endpoint
    using the token. Public-tier documents are freely downloadable;
    NDA/contract tier requires a valid auth token before the signed URL
    is issued.
    """
    doc = (
        db.query(TrustDocument)
        .filter(TrustDocument.id == document_id, TrustDocument.is_active == True)  # noqa: E712
        .first()
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    # NDA/contract tier documents require authentication before issuing URL
    if doc.classification_tier in ("nda", "contract"):
        if not authorization and not x_api_key:
            raise HTTPException(
                status_code=401,
                detail="Authentication required for NDA/contract-tier documents.",
            )
        # Validate the credentials — raises 401 on failure
        get_current_user(request, authorization, x_api_key, db)
        log.info(
            "Authenticated download URL request for %s-tier document %s",
            doc.classification_tier,
            document_id,
        )

    expires_at = int(time.time()) + _DOWNLOAD_URL_TTL
    token = _sign_download_token(document_id, expires_at)

    # Build a relative URL; in production the API host prefix is prepended
    download_url = f"/api/v1/trust/documents/{document_id}/file?expires={expires_at}&token={token}"

    expires_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

    log.info("Download URL generated for document %s (expires %s)", document_id, expires_dt)

    return TrustDocumentDownloadResponse(
        document_id=document_id,
        title=doc.title,
        download_url=download_url,
        expires_at=expires_dt,
    )


@router.get("/documents/{document_id}/file")
async def serve_trust_document(
    document_id: str,
    expires: int,
    token: str,
    request: Request,
    db: Session = Depends(get_db),
    authorization: str | None = Header(None),
    x_api_key: str | None = Header(None),
):
    """Serve the raw document file, validating the signed token and TTL.

    For NDA/contract-tier documents, a valid auth token is required in
    addition to the HMAC download signature.
    """
    import os
    from fastapi.responses import FileResponse

    if not _verify_download_token(document_id, expires, token):
        raise HTTPException(status_code=403, detail="Invalid or expired download token.")

    doc = (
        db.query(TrustDocument)
        .filter(TrustDocument.id == document_id, TrustDocument.is_active == True)  # noqa: E712
        .first()
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")

    # NDA/contract tier: require valid auth even with a valid HMAC token
    if doc.classification_tier in ("nda", "contract"):
        if not authorization and not x_api_key:
            raise HTTPException(
                status_code=401,
                detail="Authentication required to download NDA/contract-tier documents.",
            )
        get_current_user(request, authorization, x_api_key, db)

    if not os.path.isfile(doc.file_path):
        log.error("Trust document file missing on disk: %s", doc.file_path)
        raise HTTPException(status_code=500, detail="Document file unavailable.")

    return FileResponse(
        path=doc.file_path,
        media_type=doc.content_type or "application/octet-stream",
        filename=f"{doc.title.replace(' ', '_')}.pdf",
    )


@router.get("/access-requests/{request_id}/documents", response_model=list[TrustDocumentResponse])
async def list_documents_for_access_request(
    request_id: str,
    db: Session = Depends(get_db),
):
    """After NDA approval, list the documents accessible under this access request.

    Returns documents whose classification_tier is 'public' or 'nda' if the
    request is approved, 'public' only if still pending/denied.
    """
    req = db.query(TrustAccessRequest).filter(TrustAccessRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Access request not found.")

    if req.status == "approved":
        allowed_tiers = ["public", "nda"]
    else:
        allowed_tiers = ["public"]

    docs = (
        db.query(TrustDocument)
        .filter(
            TrustDocument.is_active == True,  # noqa: E712
            TrustDocument.classification_tier.in_(allowed_tiers),
        )
        .order_by(TrustDocument.classification_tier, TrustDocument.uploaded_at.desc())
        .all()
    )

    return [_doc_to_response(d) for d in docs]
