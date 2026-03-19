"""Public trust portal endpoints. No authentication required.

Exposes high-level compliance posture without sensitive details.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.api.deps import get_db
from fastapi import Depends

from warlock.db.models import (
    AuditEngagement,
    ControlResult,
    PostureSnapshot,
    TrustAccessRequest,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/trust", tags=["Trust Portal"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class FrameworkStatus(BaseModel):
    framework: str
    posture_score: float
    total_controls: int
    compliant: int
    non_compliant: int
    partial: int
    compliance_rate: float


class TrustStatusResponse(BaseModel):
    overall_posture_score: float
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
            db.query(PostureSnapshot)
            .filter(PostureSnapshot.snapshot_date == latest_date)
            .all()
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
            compliance_rate = (
                (data["compliant"] / data["total"] * 100) if data["total"] else 0
            )
            overall_scores.append(avg_score)
            frameworks.append(
                FrameworkStatus(
                    framework=fw,
                    posture_score=round(avg_score, 1),
                    total_controls=data["total"],
                    compliant=data["compliant"],
                    non_compliant=data["non_compliant"],
                    partial=data["partial"],
                    compliance_rate=round(compliance_rate, 1),
                )
            )

    overall = round(sum(overall_scores) / len(overall_scores), 1) if overall_scores else 0

    # Last assessment
    last_result = (
        db.query(ControlResult)
        .order_by(ControlResult.assessed_at.desc())
        .first()
    )
    last_assessment = None
    if last_result and last_result.assessed_at:
        dt = last_result.assessed_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        last_assessment = dt.isoformat()

    return TrustStatusResponse(
        overall_posture_score=overall,
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

    if not body.contact_email or "@" not in body.contact_email:
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

    log.info("Trust portal access request from %s (%s): %s", body.contact_name, body.company_name, req.id)

    return AccessRequestSubmitResponse(
        request_id=req.id,
        message="Your request has been submitted. You will be contacted within 2 business days.",
        status="pending",
    )
