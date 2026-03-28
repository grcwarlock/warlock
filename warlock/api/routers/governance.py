"""Governance routes: issues, attestations, engagements, POA&Ms, comments."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission, apply_framework_scope
from warlock.api.routers.schemas import (
    MessageResponse,
    PaginatedResponse,
    _dt_str,
    _parse_dt,
)
from warlock.db.models import (
    Attestation,
    AuditComment,
    AuditEngagement,
    ControlMapping,
    ControlResult,
    Finding,
    Issue,
    POAM,
    User,
)
from warlock.db.repository import get_repos

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models — Issues
# ---------------------------------------------------------------------------


class IssueCreateRequest(BaseModel):
    title: str
    description: str | None = None
    framework: str | None = None
    control_id: str | None = None
    priority: str = "medium"
    assigned_to: str | None = None
    due_date: str | None = None
    source: str = "manual"


class IssueUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    priority: str | None = None
    due_date: str | None = None
    remediation_plan: str | None = None
    tags: list[str] | None = None


class IssueTransitionRequest(BaseModel):
    status: str
    notes: str | None = None


class IssueAssignRequest(BaseModel):
    assigned_to: str


class IssueRiskAcceptRequest(BaseModel):
    owner: str
    justification: str
    expiry_days: int = 90


class IssueEvidenceRequest(BaseModel):
    description: str
    url: str


class IssueCommentRequest(BaseModel):
    content: str
    comment_type: str = "comment"


class IssueResponse(BaseModel):
    id: str
    title: str
    description: str | None = None
    finding_id: str | None = None
    control_result_id: str | None = None
    framework: str | None = None
    control_id: str | None = None
    status: str
    priority: str
    assigned_to: str | None = None
    assigned_by: str | None = None
    assigned_at: str | None = None
    due_date: str | None = None
    remediated_at: str | None = None
    verified_at: str | None = None
    closed_at: str | None = None
    risk_accepted: bool
    risk_acceptance_owner: str | None = None
    risk_acceptance_expiry: str | None = None
    risk_acceptance_justification: str | None = None
    remediation_plan: str | None = None
    remediation_evidence: list[dict[str, Any]] | None = None
    verification_notes: str | None = None
    source: str | None = None
    tags: list[str] | None = None
    created_at: str
    updated_at: str | None = None
    created_by: str | None = None

    model_config = {"from_attributes": True}


class IssueCommentResponse(BaseModel):
    id: str
    issue_id: str
    author: str
    content: str
    comment_type: str
    created_at: str

    model_config = {"from_attributes": True}


class IssueDetailResponse(BaseModel):
    issue: IssueResponse
    comments: list[IssueCommentResponse]


class IssueSummaryResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    by_priority: dict[str, int]
    overdue: int


class IssueAutoCreateRequest(BaseModel):
    framework: str | None = None


# ---------------------------------------------------------------------------
# Models — Engagements
# ---------------------------------------------------------------------------


class EngagementCreateRequest(BaseModel):
    name: str
    framework: str
    period_start: str
    period_end: str
    auditor_name: str | None = None
    auditor_firm: str | None = None
    in_scope_controls: list[str] = Field(default_factory=list)
    excluded_controls: list[str] = Field(default_factory=list)


class EngagementUpdateRequest(BaseModel):
    name: str | None = None
    status: str | None = None
    auditor_name: str | None = None
    auditor_firm: str | None = None
    in_scope_controls: list[str] | None = None
    excluded_controls: list[str] | None = None


class EngagementResponse(BaseModel):
    id: str
    name: str
    framework: str
    period_start: str
    period_end: str
    status: str
    auditor_name: str | None = None
    auditor_firm: str | None = None
    in_scope_controls: list[str]
    excluded_controls: list[str]
    created_at: str
    completed_at: str | None = None

    model_config = {"from_attributes": True}


class EvidenceResponse(BaseModel):
    engagement_id: str
    framework: str
    period_start: str
    period_end: str
    findings_count: int
    results_count: int
    findings: list[Any]
    results: list[Any]


# ---------------------------------------------------------------------------
# Models — Attestations
# ---------------------------------------------------------------------------


class AttestationCreateRequest(BaseModel):
    framework: str
    statement: str
    control_id: str | None = None
    engagement_id: str | None = None


class AttestationResponse(BaseModel):
    id: str
    engagement_id: str | None = None
    framework: str
    control_id: str | None = None
    status: str
    statement: str
    evidence_references: list[dict[str, Any]] | None = None
    prepared_by: str | None = None
    prepared_at: str | None = None
    submitted_by: str | None = None
    submitted_at: str | None = None
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_notes: str | None = None
    approved_by: str | None = None
    approved_at: str | None = None
    rejected_by: str | None = None
    rejected_at: str | None = None
    rejection_reason: str | None = None
    created_at: str
    updated_at: str | None = None

    model_config = {"from_attributes": True}


class AttestationReviewRequest(BaseModel):
    notes: str | None = None


class AttestationRejectRequest(BaseModel):
    reason: str


class GenerateAssertionRequest(BaseModel):
    framework: str


# ---------------------------------------------------------------------------
# Models — Audit Comments
# ---------------------------------------------------------------------------


class AuditCommentCreateRequest(BaseModel):
    target_type: str
    target_id: str
    author_role: str | None = None
    content: str
    parent_id: str | None = None


class AuditCommentResponse(BaseModel):
    id: str
    engagement_id: str
    target_type: str
    target_id: str
    author: str
    author_role: str | None = None
    content: str
    parent_id: str | None = None
    resolved: bool
    resolved_by: str | None = None
    resolved_at: str | None = None
    created_at: str

    model_config = {"from_attributes": True}


class UnresolvedCountResponse(BaseModel):
    engagement_id: str
    unresolved: int


# ---------------------------------------------------------------------------
# Models — POA&M, Compensating Controls, Risk Acceptance
# ---------------------------------------------------------------------------


class POAMResponse(BaseModel):
    id: str
    framework: str
    control_id: str
    weakness_description: str
    severity: str
    status: str
    scheduled_completion: str | None
    delay_count: int
    milestones: list[dict] | None
    created_at: str

    model_config = {"from_attributes": True}


class POAMCreateRequest(BaseModel):
    title: str
    framework: str
    control_id: str
    weakness_description: str
    severity: str = "medium"
    scheduled_completion: str | None = None


class POAMUpdateRequest(BaseModel):
    weakness_description: str | None = None
    severity: str | None = None
    risk_level: str | None = None
    resources_required: str | None = None
    vendor_dependency: str | None = None


class POAMTransitionRequest(BaseModel):
    status: str
    notes: str | None = None


class POAMExtendRequest(BaseModel):
    justification: str
    new_completion_date: str
    approved_by: str


class CompensatingControlResponse(BaseModel):
    id: str
    original_framework: str
    original_control_id: str
    title: str
    status: str
    effectiveness_score: float | None
    expiry_date: str | None
    created_at: str

    model_config = {"from_attributes": True}


class RiskAcceptanceResponse(BaseModel):
    id: str
    framework: str
    control_id: str
    risk_level: str
    status: str
    approved_by: str | None
    expiry_date: str
    created_at: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issue_to_response(issue: Issue) -> IssueResponse:
    return IssueResponse(
        id=issue.id,
        title=issue.title,
        description=issue.description,
        finding_id=issue.finding_id,
        control_result_id=issue.control_result_id,
        framework=issue.framework,
        control_id=issue.control_id,
        status=issue.status,
        priority=issue.priority,
        assigned_to=issue.assigned_to,
        assigned_by=issue.assigned_by,
        assigned_at=_dt_str(issue.assigned_at),
        due_date=_dt_str(issue.due_date),
        remediated_at=_dt_str(issue.remediated_at),
        verified_at=_dt_str(issue.verified_at),
        closed_at=_dt_str(issue.closed_at),
        risk_accepted=issue.risk_accepted or False,
        risk_acceptance_owner=issue.risk_acceptance_owner,
        risk_acceptance_expiry=_dt_str(issue.risk_acceptance_expiry),
        risk_acceptance_justification=issue.risk_acceptance_justification,
        remediation_plan=issue.remediation_plan,
        remediation_evidence=issue.remediation_evidence,
        verification_notes=issue.verification_notes,
        source=issue.source,
        tags=issue.tags,
        created_at=_dt_str(issue.created_at) or "",
        updated_at=_dt_str(issue.updated_at),
        created_by=issue.created_by,
    )


def _engagement_to_response(eng: AuditEngagement) -> EngagementResponse:
    return EngagementResponse(
        id=eng.id,
        name=eng.name,
        framework=eng.framework,
        period_start=_dt_str(eng.period_start) or "",
        period_end=_dt_str(eng.period_end) or "",
        status=eng.status,
        auditor_name=eng.auditor_name,
        auditor_firm=eng.auditor_firm,
        in_scope_controls=eng.in_scope_controls or [],
        excluded_controls=eng.excluded_controls or [],
        created_at=_dt_str(eng.created_at) or "",
        completed_at=_dt_str(eng.completed_at),
    )


def _attestation_to_response(att: Attestation) -> AttestationResponse:
    return AttestationResponse(
        id=att.id,
        engagement_id=att.engagement_id,
        framework=att.framework,
        control_id=att.control_id,
        status=att.status,
        statement=att.statement,
        evidence_references=att.evidence_references,
        prepared_by=att.prepared_by,
        prepared_at=_dt_str(att.prepared_at),
        submitted_by=att.submitted_by,
        submitted_at=_dt_str(att.submitted_at),
        reviewed_by=att.reviewed_by,
        reviewed_at=_dt_str(att.reviewed_at),
        review_notes=att.review_notes,
        approved_by=att.approved_by,
        approved_at=_dt_str(att.approved_at),
        rejected_by=att.rejected_by,
        rejected_at=_dt_str(att.rejected_at),
        rejection_reason=att.rejection_reason,
        created_at=_dt_str(att.created_at) or "",
        updated_at=_dt_str(att.updated_at),
    )


def _audit_comment_to_response(c: AuditComment) -> AuditCommentResponse:
    return AuditCommentResponse(
        id=c.id,
        engagement_id=c.engagement_id,
        target_type=c.target_type,
        target_id=c.target_id,
        author=c.author,
        author_role=c.author_role,
        content=c.content,
        parent_id=c.parent_id,
        resolved=c.resolved or False,
        resolved_by=c.resolved_by,
        resolved_at=_dt_str(c.resolved_at),
        created_at=_dt_str(c.created_at) or "",
    )


# ---------------------------------------------------------------------------
# Routes — Issues
# ---------------------------------------------------------------------------


@router.get("/issues/summary", response_model=IssueSummaryResponse)
def issues_summary(
    framework: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    summary = mgr.summary(db, framework=framework)
    return IssueSummaryResponse(**summary)


@router.get("/issues", response_model=PaginatedResponse)
def list_issues(
    issue_status: str | None = Query(None, alias="status"),
    priority: str | None = Query(None),
    framework: str | None = Query(None),
    assigned_to: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(Issue)
    # S-1: Apply ABAC scope filters
    query = apply_framework_scope(query, Issue, current_user)
    if issue_status:
        query = query.filter(Issue.status == issue_status)
    if priority:
        query = query.filter(Issue.priority == priority)
    if framework:
        query = query.filter(Issue.framework == framework)
    if assigned_to:
        query = query.filter(Issue.assigned_to == assigned_to)

    total = query.count()
    rows = query.order_by(Issue.created_at.desc()).offset(offset).limit(limit).all()
    items = [_issue_to_response(i) for i in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/issues", response_model=IssueResponse, status_code=201)
def create_issue(
    body: IssueCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    issue = mgr.create_from_poam(
        db,
        framework=body.framework or "",
        control_id=body.control_id or "",
        title=body.title,
        description=body.description or "",
        priority=body.priority,
        created_by=current_user.email,
    )
    if body.assigned_to:
        mgr.assign(db, issue.id, body.assigned_to, current_user.email)
    if body.due_date:
        issue.due_date = _parse_dt(body.due_date)
    issue.source = body.source
    db.flush()
    return _issue_to_response(issue)


@router.get("/issues/{issue_id}", response_model=IssueDetailResponse)
def get_issue(
    issue_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    issue = repos.issues.get(issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    comments = repos.issues.comments_for_issue(issue_id)
    return IssueDetailResponse(
        issue=_issue_to_response(issue),
        comments=[
            IssueCommentResponse(
                id=c.id,
                issue_id=c.issue_id,
                author=c.author,
                content=c.content,
                comment_type=c.comment_type or "comment",
                created_at=_dt_str(c.created_at) or "",
            )
            for c in comments
        ],
    )


@router.patch("/issues/{issue_id}", response_model=IssueResponse)
def update_issue(
    issue_id: str,
    body: IssueUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    repos = get_repos(db)
    issue = repos.issues.get(issue_id)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    if body.title is not None:
        issue.title = body.title
    if body.description is not None:
        issue.description = body.description
    if body.priority is not None:
        issue.priority = body.priority
    if body.due_date is not None:
        issue.due_date = _parse_dt(body.due_date)
    if body.remediation_plan is not None:
        issue.remediation_plan = body.remediation_plan
    if body.tags is not None:
        issue.tags = body.tags
    issue.updated_at = datetime.now(timezone.utc)
    db.flush()
    return _issue_to_response(issue)


@router.post("/issues/{issue_id}/transition", response_model=IssueResponse)
def transition_issue(
    issue_id: str,
    body: IssueTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    try:
        issue = mgr.transition(db, issue_id, body.status, current_user.email, body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _issue_to_response(issue)


@router.post("/issues/{issue_id}/assign", response_model=IssueResponse)
def assign_issue(
    issue_id: str,
    body: IssueAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    try:
        issue = mgr.assign(db, issue_id, body.assigned_to, current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _issue_to_response(issue)


@router.post("/issues/{issue_id}/accept-risk", response_model=IssueResponse)
def accept_risk_issue(
    issue_id: str,
    body: IssueRiskAcceptRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    try:
        issue = mgr.accept_risk(
            db,
            issue_id,
            body.owner,
            body.justification,
            body.expiry_days,
            actor=current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _issue_to_response(issue)


@router.post("/issues/{issue_id}/evidence", response_model=IssueResponse)
def add_issue_evidence(
    issue_id: str,
    body: IssueEvidenceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    try:
        issue = mgr.add_evidence(db, issue_id, body.description, body.url, current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _issue_to_response(issue)


@router.post("/issues/{issue_id}/comments", response_model=IssueCommentResponse, status_code=201)
def add_issue_comment(
    issue_id: str,
    body: IssueCommentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    try:
        comment = mgr.add_comment(db, issue_id, current_user.email, body.content, body.comment_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return IssueCommentResponse(
        id=comment.id,
        issue_id=comment.issue_id,
        author=comment.author,
        content=comment.content,
        comment_type=comment.comment_type or "comment",
        created_at=_dt_str(comment.created_at) or "",
    )


@router.post("/issues/auto-create", response_model=list[IssueResponse])
def auto_create_issues(
    body: IssueAutoCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager

    mgr = IssueManager()
    issues = mgr.auto_create_from_results(db, framework=body.framework)
    return [_issue_to_response(i) for i in issues]


# ---------------------------------------------------------------------------
# Routes — Attestations
# ---------------------------------------------------------------------------


@router.get("/attestations", response_model=list[AttestationResponse])
def list_attestations(
    engagement_id: str | None = Query(None),
    framework: str | None = Query(None),
    attest_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(Attestation)
    # S-1: Apply ABAC scope filters
    query = apply_framework_scope(query, Attestation, current_user)
    if engagement_id:
        query = query.filter(Attestation.engagement_id == engagement_id)
    if framework:
        query = query.filter(Attestation.framework == framework)
    if attest_status:
        query = query.filter(Attestation.status == attest_status)
    rows = query.order_by(Attestation.created_at.desc()).offset(offset).limit(limit).all()
    return [_attestation_to_response(a) for a in rows]


@router.post("/attestations", response_model=AttestationResponse, status_code=201)
def create_attestation(
    body: AttestationCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AttestationManager

    mgr = AttestationManager()
    try:
        att = mgr.create(
            db,
            framework=body.framework,
            statement=body.statement,
            prepared_by=current_user.email,
            control_id=body.control_id,
            engagement_id=body.engagement_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


@router.get("/attestations/{attestation_id}", response_model=AttestationResponse)
def get_attestation(
    attestation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    att = repos.attestations.get(attestation_id)
    if not att:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return _attestation_to_response(att)


@router.post("/attestations/{attestation_id}/submit", response_model=AttestationResponse)
def submit_attestation(
    attestation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AttestationManager

    mgr = AttestationManager()
    try:
        att = mgr.submit(db, attestation_id, current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


@router.post("/attestations/{attestation_id}/review", response_model=AttestationResponse)
def review_attestation(
    attestation_id: str,
    body: AttestationReviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    repos = get_repos(db)
    attest = repos.attestations.get(attestation_id)
    if not attest:
        raise HTTPException(status_code=404, detail="Attestation not found")
    if attest.prepared_by and attest.prepared_by == current_user.email:
        raise HTTPException(
            status_code=403,
            detail="Separation of duties: reviewer cannot be the same as preparer",
        )
    from warlock.workflows.attestations import AttestationManager

    mgr = AttestationManager()
    try:
        att = mgr.review(db, attestation_id, current_user.email, body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


@router.post("/attestations/{attestation_id}/approve", response_model=AttestationResponse)
def approve_attestation(
    attestation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    repos = get_repos(db)
    attest = repos.attestations.get(attestation_id)
    if not attest:
        raise HTTPException(status_code=404, detail="Attestation not found")
    if attest.prepared_by and attest.prepared_by == current_user.email:
        raise HTTPException(
            status_code=403,
            detail="Separation of duties: approver cannot be the same as preparer",
        )
    if attest.reviewed_by and attest.reviewed_by == current_user.email:
        raise HTTPException(
            status_code=403,
            detail="Separation of duties: approver cannot be the same as reviewer",
        )
    from warlock.workflows.attestations import AttestationManager

    mgr = AttestationManager()
    try:
        att = mgr.approve(db, attestation_id, current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


@router.post("/attestations/{attestation_id}/reject", response_model=AttestationResponse)
def reject_attestation(
    attestation_id: str,
    body: AttestationRejectRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AttestationManager

    mgr = AttestationManager()
    try:
        att = mgr.reject(db, attestation_id, current_user.email, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


# ---------------------------------------------------------------------------
# Routes — Engagements
# ---------------------------------------------------------------------------


@router.get("/engagements", response_model=list[EngagementResponse])
def list_engagements(
    framework: str | None = Query(None),
    engagement_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(AuditEngagement)
    # S-1: Apply ABAC scope filters
    query = apply_framework_scope(query, AuditEngagement, current_user)
    if framework:
        query = query.filter(AuditEngagement.framework == framework)
    if engagement_status:
        query = query.filter(AuditEngagement.status == engagement_status)

    rows = query.order_by(AuditEngagement.created_at.desc()).offset(offset).limit(limit).all()
    return [_engagement_to_response(e) for e in rows]


@router.post("/engagements", response_model=EngagementResponse, status_code=201)
def create_engagement(
    body: EngagementCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    eng = AuditEngagement(
        name=body.name,
        framework=body.framework,
        period_start=_parse_dt(body.period_start),
        period_end=_parse_dt(body.period_end),
        auditor_name=body.auditor_name,
        auditor_firm=body.auditor_firm,
        in_scope_controls=body.in_scope_controls,
        excluded_controls=body.excluded_controls,
    )
    db.add(eng)
    db.flush()
    return _engagement_to_response(eng)


@router.get("/engagements/{engagement_id}", response_model=EngagementResponse)
def get_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    eng = repos.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return _engagement_to_response(eng)


@router.put("/engagements/{engagement_id}", response_model=EngagementResponse)
def update_engagement(
    engagement_id: str,
    body: EngagementUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    repos = get_repos(db)
    eng = repos.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if body.name is not None:
        eng.name = body.name
    if body.status is not None:
        eng.status = body.status
        if body.status == "completed":
            eng.completed_at = datetime.now(timezone.utc)
    if body.auditor_name is not None:
        eng.auditor_name = body.auditor_name
    if body.auditor_firm is not None:
        eng.auditor_firm = body.auditor_firm
    if body.in_scope_controls is not None:
        eng.in_scope_controls = body.in_scope_controls
    if body.excluded_controls is not None:
        eng.excluded_controls = body.excluded_controls
    db.flush()
    return _engagement_to_response(eng)


@router.delete("/engagements/{engagement_id}", response_model=MessageResponse)
def delete_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("delete")),
):
    repos = get_repos(db)
    eng = repos.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    eng.status = "archived"
    return MessageResponse(message="Engagement archived")


@router.get("/engagements/{engagement_id}/evidence", response_model=EvidenceResponse)
def engagement_evidence(
    engagement_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    eng = repos.engagements.get(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    # Findings within the engagement period and framework
    findings_query = (
        db.query(Finding)
        .join(ControlMapping, ControlMapping.finding_id == Finding.id)
        .filter(
            ControlMapping.framework == eng.framework,
            Finding.observed_at >= eng.period_start,
            Finding.observed_at <= eng.period_end,
        )
    )

    # Apply scope filtering
    if eng.in_scope_controls:
        findings_query = findings_query.filter(ControlMapping.control_id.in_(eng.in_scope_controls))
    if eng.excluded_controls:
        findings_query = findings_query.filter(
            ~ControlMapping.control_id.in_(eng.excluded_controls)
        )

    findings_total = findings_query.count()
    findings_rows = (
        findings_query.order_by(Finding.observed_at.desc()).offset(offset).limit(limit).all()
    )

    # Results within the engagement period and framework
    results_query = db.query(ControlResult).filter(
        ControlResult.framework == eng.framework,
        ControlResult.assessed_at >= eng.period_start,
        ControlResult.assessed_at <= eng.period_end,
    )
    if eng.in_scope_controls:
        results_query = results_query.filter(ControlResult.control_id.in_(eng.in_scope_controls))
    if eng.excluded_controls:
        results_query = results_query.filter(~ControlResult.control_id.in_(eng.excluded_controls))

    results_total = results_query.count()
    results_rows = (
        results_query.order_by(ControlResult.assessed_at.desc()).offset(offset).limit(limit).all()
    )

    return EvidenceResponse(
        engagement_id=eng.id,
        framework=eng.framework,
        period_start=_dt_str(eng.period_start) or "",
        period_end=_dt_str(eng.period_end) or "",
        findings_count=findings_total,
        results_count=results_total,
        findings=[
            {
                "id": f.id,
                "title": f.title,
                "observation_type": f.observation_type,
                "severity": f.severity,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "source": f.source,
                "provider": f.provider,
                "observed_at": _dt_str(f.observed_at) or "",
                "detail": f.detail,
            }
            for f in findings_rows
        ],
        results=[
            {
                "id": r.id,
                "framework": r.framework,
                "control_id": r.control_id,
                "status": r.status,
                "severity": r.severity,
                "assessor": r.assessor,
                "assertion_name": r.assertion_name,
                "assertion_passed": r.assertion_passed,
                "assessed_at": _dt_str(r.assessed_at) or "",
                "finding_id": r.finding_id,
                "remediation_summary": r.remediation_summary,
            }
            for r in results_rows
        ],
    )


@router.get("/engagements/{engagement_id}/package")
def get_audit_package(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("export")),
):
    """Build and return the complete audit evidence package."""
    from warlock.export.auditor import AuditorWorkflow

    repos = get_repos(db)
    engagement = repos.engagements.get(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    workflow = AuditorWorkflow()
    try:
        package = workflow.build_audit_package(db, engagement_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return json.loads(workflow.export_package_json(package))


@router.post("/engagements/{engagement_id}/generate-assertion", response_model=AttestationResponse)
def generate_assertion(
    engagement_id: str,
    body: GenerateAssertionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AttestationManager

    mgr = AttestationManager()
    try:
        att = mgr.generate_management_assertion(db, engagement_id, body.framework)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


# ---------------------------------------------------------------------------
# Routes — Audit Comments
# ---------------------------------------------------------------------------


@router.get("/engagements/{engagement_id}/comments", response_model=list[AuditCommentResponse])
def list_engagement_comments(
    engagement_id: str,
    target_type: str | None = Query(None),
    resolved: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(AuditComment).filter(AuditComment.engagement_id == engagement_id)
    if target_type:
        query = query.filter(AuditComment.target_type == target_type)
    if resolved is not None:
        query = query.filter(AuditComment.resolved == resolved)
    rows = query.order_by(AuditComment.created_at.asc()).offset(offset).limit(limit).all()
    return [_audit_comment_to_response(c) for c in rows]


@router.post(
    "/engagements/{engagement_id}/comments",
    response_model=AuditCommentResponse,
    status_code=201,
)
def add_engagement_comment(
    engagement_id: str,
    body: AuditCommentCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AuditCollaboration

    collab = AuditCollaboration()
    try:
        comment = collab.add_comment(
            db,
            engagement_id,
            body.target_type,
            body.target_id,
            current_user.email,
            body.author_role or "practitioner",
            body.content,
            body.parent_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _audit_comment_to_response(comment)


@router.post("/comments/{comment_id}/resolve", response_model=AuditCommentResponse)
def resolve_comment(
    comment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AuditCollaboration

    collab = AuditCollaboration()
    try:
        comment = collab.resolve_comment(db, comment_id, current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _audit_comment_to_response(comment)


@router.get(
    "/engagements/{engagement_id}/comments/unresolved",
    response_model=UnresolvedCountResponse,
)
def unresolved_comments_count(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.attestations import AuditCollaboration

    collab = AuditCollaboration()
    count = collab.unresolved_count(db, engagement_id)
    return UnresolvedCountResponse(engagement_id=engagement_id, unresolved=count)


# ---------------------------------------------------------------------------
# Routes — POA&Ms
# ---------------------------------------------------------------------------


@router.get("/poams")
def list_poams(
    framework: str | None = Query(None),
    status: str | None = Query(None),
    overdue: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List Plans of Action & Milestones."""
    from warlock.workflows.poam import POAMManager

    mgr = POAMManager()
    if overdue:
        rows = mgr.get_overdue(db)
    else:
        rows = mgr.list_poams(db, framework=framework, status=status)
    return [
        {
            "id": p.id,
            "framework": p.framework,
            "control_id": p.control_id,
            "weakness_description": p.weakness_description,
            "severity": p.severity,
            "status": p.status,
            "delay_count": p.delay_count or 0,
            "scheduled_completion": p.scheduled_completion.isoformat()
            if p.scheduled_completion
            else None,
            "milestones": p.milestones,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in rows
    ]


@router.post("/poams/{poam_id}/extend")
def extend_poam(
    poam_id: str,
    req: POAMExtendRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Extend a POA&M's scheduled completion date."""
    from warlock.workflows.poam import POAMManager
    from datetime import datetime as dt

    mgr = POAMManager()
    new_date = dt.fromisoformat(req.new_completion_date)
    poam = mgr.extend(db, poam_id, req.justification, new_date, req.approved_by)
    return {"id": poam.id, "status": poam.status, "delay_count": poam.delay_count}


@router.get("/poams/{poam_id}", response_model=POAMResponse)
def get_poam(
    poam_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Get a single POA&M by ID."""
    poam = db.get(POAM, poam_id)
    if not poam:
        raise HTTPException(status_code=404, detail="POA&M not found")
    return POAMResponse(
        id=poam.id,
        framework=poam.framework,
        control_id=poam.control_id,
        weakness_description=poam.weakness_description,
        severity=poam.severity,
        status=poam.status,
        scheduled_completion=(
            poam.scheduled_completion.isoformat() if poam.scheduled_completion else None
        ),
        delay_count=poam.delay_count or 0,
        milestones=poam.milestones,
        created_at=poam.created_at.isoformat() if poam.created_at else "",
    )


@router.post("/poams", response_model=POAMResponse, status_code=201)
def create_poam(
    body: POAMCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Create a new POA&M."""
    poam = POAM(
        framework=body.framework,
        control_id=body.control_id,
        weakness_description=body.weakness_description,
        severity=body.severity,
        status="draft",
        created_by=current_user.email,
    )
    if body.scheduled_completion:
        poam.scheduled_completion = _parse_dt(body.scheduled_completion)
    db.add(poam)
    db.flush()
    return POAMResponse(
        id=poam.id,
        framework=poam.framework,
        control_id=poam.control_id,
        weakness_description=poam.weakness_description,
        severity=poam.severity,
        status=poam.status,
        scheduled_completion=(
            poam.scheduled_completion.isoformat() if poam.scheduled_completion else None
        ),
        delay_count=poam.delay_count or 0,
        milestones=poam.milestones,
        created_at=poam.created_at.isoformat() if poam.created_at else "",
    )


@router.patch("/poams/{poam_id}", response_model=POAMResponse)
def update_poam(
    poam_id: str,
    body: POAMUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Update mutable fields on a POA&M."""
    poam = db.get(POAM, poam_id)
    if not poam:
        raise HTTPException(status_code=404, detail="POA&M not found")
    if body.weakness_description is not None:
        poam.weakness_description = body.weakness_description
    if body.severity is not None:
        poam.severity = body.severity
    if body.risk_level is not None:
        poam.risk_level = body.risk_level
    if body.resources_required is not None:
        poam.resources_required = body.resources_required
    if body.vendor_dependency is not None:
        poam.vendor_dependency = body.vendor_dependency
    poam.updated_by = current_user.email
    db.flush()
    return POAMResponse(
        id=poam.id,
        framework=poam.framework,
        control_id=poam.control_id,
        weakness_description=poam.weakness_description,
        severity=poam.severity,
        status=poam.status,
        scheduled_completion=(
            poam.scheduled_completion.isoformat() if poam.scheduled_completion else None
        ),
        delay_count=poam.delay_count or 0,
        milestones=poam.milestones,
        created_at=poam.created_at.isoformat() if poam.created_at else "",
    )


@router.post("/poams/{poam_id}/transition", response_model=MessageResponse)
def transition_poam(
    poam_id: str,
    body: POAMTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    """Transition a POA&M to a new status."""
    from warlock.workflows.poam import POAMManager

    mgr = POAMManager()
    try:
        poam = mgr.transition(db, poam_id, body.status, actor=current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return MessageResponse(message=f"POA&M {poam.id} transitioned to '{poam.status}'")


# ---------------------------------------------------------------------------
# Routes — Compensating Controls
# ---------------------------------------------------------------------------


@router.get("/compensating-controls")
def list_compensating_controls(
    framework: str | None = Query(None),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List compensating controls."""
    from warlock.workflows.compensating import CompensatingControlManager

    mgr = CompensatingControlManager()
    rows = mgr.list_controls(db, framework=framework, status=status)
    return [
        {
            "id": c.id,
            "original_framework": c.original_framework,
            "original_control_id": c.original_control_id,
            "title": c.title,
            "status": c.status,
            "effectiveness_score": c.effectiveness_score,
            "expiry_date": c.expiry_date.isoformat() if c.expiry_date else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in rows
    ]


# ---------------------------------------------------------------------------
# Routes — Risk Acceptances
# ---------------------------------------------------------------------------


@router.get("/risk-acceptances")
def list_risk_acceptances(
    framework: str | None = Query(None),
    status: str | None = Query(None),
    expiring_days: int | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List risk acceptances."""
    from warlock.workflows.risk_acceptance import RiskAcceptanceManager

    mgr = RiskAcceptanceManager()
    rows = mgr.list_acceptances(db, framework=framework, status=status, expiring_days=expiring_days)
    return [
        {
            "id": r.id,
            "framework": r.framework,
            "control_id": r.control_id,
            "risk_level": r.risk_level,
            "status": r.status,
            "approved_by": r.approved_by,
            "expiry_date": r.expiry_date.isoformat() if r.expiry_date else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# STUB-012: SoD Analysis API endpoint
# ---------------------------------------------------------------------------

# SoD conflict rule definitions (mirrors CLI sod_cmd.py)
_SOD_RULES: list[tuple[str, str, str]] = [
    ("admin", "auditor", "Admins should not perform self-audits"),
    ("admin", "owner", "Admin and system owner create unilateral control"),
    ("owner", "auditor", "System owners auditing their own systems lack independence"),
    ("admin", "viewer", "Admin-viewer duality is low risk but non-standard"),
]

_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin": ["manage_users", "configure_systems", "delete_data", "approve_changes"],
    "auditor": ["read_all", "export_results", "create_findings", "sign_reports"],
    "owner": ["update_controls", "accept_risks", "manage_poams", "approve_exceptions"],
    "viewer": ["read_results", "read_findings"],
}


@router.get("/sod-analysis")
def sod_analysis_endpoint(
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
) -> dict:
    """Segregation of Duties analysis across all active users."""
    users = db.query(User).filter(User.is_active.is_(True)).all()

    conflicts: list[dict] = []
    for user in users:
        user_roles: list[str] = [user.role]
        perms = set(user.allowed_actions or [])
        for role, role_perms in _ROLE_PERMISSIONS.items():
            if role != user.role and perms.issuperset(role_perms):
                user_roles.append(role)

        for rule_a, rule_b, desc in _SOD_RULES:
            roles_normalized = [r.split("(")[0] for r in user_roles]
            if rule_a in roles_normalized and rule_b in roles_normalized:
                conflicts.append(
                    {
                        "email": user.email,
                        "name": user.name,
                        "role": user.role,
                        "conflict": f"{rule_a} + {rule_b}",
                        "description": desc,
                    }
                )

    return {
        "summary": {
            "total_users": len(users),
            "users_with_conflicts": len({c["email"] for c in conflicts}),
            "total_conflicts": len(conflicts),
        },
        "conflicts": conflicts,
    }
