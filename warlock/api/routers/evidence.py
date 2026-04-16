"""Terraform module evidence submission endpoint.

Accepts self-registration POSTs from Terraform modules (via the _shared/warlock-registration submodule).
Links evidence to findings, control results, and remediations.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.deps import apply_framework_scope, get_db, require_permission
from warlock.db.models import ControlResult, Finding, Remediation, User

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class EvidenceSubmitRequest(BaseModel):
    """Payload from Terraform module self-registration."""

    module: str = Field(..., description="Domain-qualified module name (e.g. encryption/aws-kms)")
    resource_id: str = Field(
        ..., description="Cloud resource ID (ARN, Azure resource ID, GCP name)"
    )
    control_ids: list[str] = Field(
        ..., description="NIST 800-53 control IDs (e.g. ['SC-12', 'SC-28'])"
    )
    attributes: dict[str, Any] = Field(default_factory=dict, description="Compliance attributes")
    action: str = Field(default="provision", description="provision | remediate | verify")
    remediation_id: str | None = Field(default=None, description="Remediation ID for closed-loop")


class EvidenceSubmitResponse(BaseModel):
    status: str
    message: str
    evidence_id: str | None = None
    remediation_updated: bool = False


# ---------------------------------------------------------------------------
# POST /evidence
# ---------------------------------------------------------------------------


@router.post("/evidence", response_model=EvidenceSubmitResponse, status_code=201)
def submit_evidence(
    body: EvidenceSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
) -> EvidenceSubmitResponse:
    """Accept self-registration evidence from Terraform modules."""
    log.info(
        "Evidence submission: module=%s resource=%s action=%s",
        body.module,
        body.resource_id,
        body.action,
    )

    if body.action not in ("provision", "remediate", "verify"):
        raise HTTPException(
            status_code=422,
            detail=(f"Invalid action: {body.action}. Must be provision, remediate, or verify."),
        )

    evidence_entry = {
        "module": body.module,
        "resource_id": body.resource_id,
        "control_ids": body.control_ids,
        "attributes": body.attributes,
        "action": body.action,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "submitted_by": current_user.email if current_user else "terraform",
    }

    remediation_updated = False

    # If this is a remediation action, update the linked remediation (scoped)
    if body.action == "remediate" and body.remediation_id:
        remediation = (
            apply_framework_scope(db.query(Remediation), Remediation, current_user)
            .filter(Remediation.id == body.remediation_id)
            .first()
        )
        if not remediation:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation {body.remediation_id} not found",
            )

        # Append evidence to the remediation
        existing_evidence = remediation.evidence or []
        existing_evidence.append(evidence_entry)
        remediation.evidence = existing_evidence

        # Transition to verification if currently in_progress
        if remediation.status == "in_progress":
            remediation.status = "verification"
            remediation.updated_at = datetime.now(timezone.utc)
            log.info(
                "Remediation %s transitioned to verification via terraform evidence",
                body.remediation_id,
            )

        remediation_updated = True

    # For verify/provision actions, find matching findings by resource_id
    # and update control results linked to those findings for the given control IDs
    if body.action in ("verify", "provision"):
        findings = db.query(Finding).filter(Finding.resource_id == body.resource_id).all()
        finding_ids = {f.id for f in findings}

        if finding_ids:
            for control_id in body.control_ids:
                results = (
                    apply_framework_scope(db.query(ControlResult), ControlResult, current_user)
                    .filter(
                        ControlResult.control_id == control_id,
                        ControlResult.finding_id.in_(finding_ids),
                    )
                    .all()
                )
                for result in results:
                    existing_ids = result.evidence_ids or []
                    # Store the evidence entry as a structured reference
                    existing_ids.append(evidence_entry)
                    result.evidence_ids = existing_ids

    db.flush()

    return EvidenceSubmitResponse(
        status="accepted",
        message=f"Evidence for {body.module} ({body.action}) recorded",
        evidence_id=body.remediation_id,
        remediation_updated=remediation_updated,
    )
