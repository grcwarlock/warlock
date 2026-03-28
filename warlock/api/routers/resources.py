"""Resource routes: assets, vendors, personnel, data silos, and other models lacking API coverage.

Addresses GAP-020 — exposes read (and limited write) endpoints for models that
previously had no REST interface.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission
from warlock.api.routers.schemas import PaginatedResponse, _dt_str
from warlock.db.models import (
    Asset,
    ChangeEvent,
    ControlInheritance,
    DataSilo,
    EscalationPolicy,
    EvidenceRequest,
    LegalHold,
    Personnel,
    PipelineRun,
    Questionnaire,
    QuestionnaireTemplate,
    SavedQuery,
    SystemDependency,
    User,
    Vendor,
    WatchSubscription,
)

router = APIRouter()
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _paginate(
    db: Session,
    model,
    serializer,
    limit: int,
    offset: int,
    *,
    order_col=None,
    filters: list | None = None,
) -> PaginatedResponse:
    """Build a paginated response for a simple model query."""
    query = db.query(model)
    for f in filters or []:
        query = query.filter(f)
    total = query.count()
    col = order_col if order_col is not None else model.created_at.desc()
    rows = query.order_by(col).offset(offset).limit(limit).all()
    return PaginatedResponse(
        items=[serializer(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class AssetResponse(BaseModel):
    id: str
    resource_id: str
    resource_type: str
    resource_name: str | None = None
    owner: str | None = None
    classification: str | None = None
    criticality: int | None = None
    status: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None


class VendorResponse(BaseModel):
    id: str
    name: str
    tier: str | None = None
    risk_score: float | None = None
    contract_expires: str | None = None
    last_assessment: str | None = None
    blast_radius_score: float | None = None
    dependent_control_count: int | None = None


class PersonnelResponse(BaseModel):
    id: str
    email: str
    full_name: str
    department: str | None = None
    title: str | None = None
    employee_type: str | None = None
    hr_status: str | None = None
    idp_status: str | None = None
    mfa_enabled: bool | None = None
    training_status: str | None = None
    risk_score: float | None = None
    is_active: bool | None = None


class DataSiloResponse(BaseModel):
    id: str
    name: str
    silo_type: str
    provider: str | None = None
    data_classification: str | None = None
    contains_pii: bool | None = None
    contains_phi: bool | None = None
    scan_status: str | None = None
    owner: str | None = None
    is_active: bool | None = None
    created_at: str | None = None


class SystemDependencyResponse(BaseModel):
    id: str
    consumer_system_id: str
    provider_system_id: str
    dependency_type: str
    description: str | None = None
    created_at: str | None = None


class ControlInheritanceResponse(BaseModel):
    id: str
    system_profile_id: str
    framework: str
    control_id: str
    inheritance_type: str
    provider_system_id: str | None = None
    status: str | None = None
    created_at: str | None = None


class ChangeEventResponse(BaseModel):
    id: str
    source: str
    source_type: str
    event_type: str
    actor: str | None = None
    action: str
    resource_id: str | None = None
    resource_type: str | None = None
    occurred_at: str | None = None
    ingested_at: str | None = None


class PipelineRunResponse(BaseModel):
    id: str
    status: str
    connectors_succeeded: int | None = None
    connectors_failed: int | None = None
    raw_events_collected: int | None = None
    findings_normalized: int | None = None
    controls_mapped: int | None = None
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    triggered_by: str | None = None


class SavedQueryResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    query_type: str | None = None
    shared: bool | None = None
    created_by: str | None = None
    created_at: str | None = None
    last_run_at: str | None = None
    run_count: int | None = None


class SavedQueryCreateRequest(BaseModel):
    name: str
    description: str | None = None
    sql_text: str
    query_type: str = "custom"
    parameters: dict[str, Any] | None = None
    shared: bool = False


class WatchSubscriptionResponse(BaseModel):
    id: str
    user_id: str
    entity_type: str
    entity_id: str
    created_at: str | None = None


class WatchSubscriptionCreateRequest(BaseModel):
    entity_type: str
    entity_id: str


class EscalationPolicyResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    levels: list[Any] | None = None
    cooldown_minutes: int | None = None
    active: bool | None = None
    entity_types: list[str] | None = None
    min_severity: str | None = None
    created_at: str | None = None


class LegalHoldResponse(BaseModel):
    id: str
    reason: str
    start_date: str | None = None
    end_date: str | None = None
    created_by: str | None = None
    is_active: bool | None = None
    framework: str | None = None
    created_at: str | None = None


class EvidenceRequestResponse(BaseModel):
    id: str
    engagement_id: str
    auditor_id: str
    framework: str | None = None
    control_id: str | None = None
    description: str
    status: str | None = None
    fulfilled_by: str | None = None
    fulfilled_at: str | None = None
    created_at: str | None = None


class EvidenceRequestCreateRequest(BaseModel):
    engagement_id: str
    auditor_id: str
    framework: str | None = None
    control_id: str | None = None
    description: str


class QuestionnaireTemplateResponse(BaseModel):
    id: str
    name: str
    template_type: str
    version: str | None = None
    description: str | None = None
    total_questions: int | None = None
    is_active: bool | None = None
    created_at: str | None = None


class QuestionnaireResponse(BaseModel):
    id: str
    template_id: str
    vendor_name: str
    vendor_contact_email: str | None = None
    status: str | None = None
    completion_pct: float | None = None
    risk_score: float | None = None
    due_date: str | None = None
    created_at: str | None = None


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------


def _asset(r: Asset) -> dict:
    return AssetResponse(
        id=r.id,
        resource_id=r.resource_id,
        resource_type=r.resource_type,
        resource_name=r.resource_name,
        owner=r.owner,
        classification=r.classification,
        criticality=r.criticality,
        status=r.status,
        first_seen=_dt_str(r.first_seen),
        last_seen=_dt_str(r.last_seen),
    ).model_dump()


def _vendor(r: Vendor) -> dict:
    return VendorResponse(
        id=r.id,
        name=r.name,
        tier=r.tier,
        risk_score=r.risk_score,
        contract_expires=_dt_str(r.contract_expires),
        last_assessment=_dt_str(r.last_assessment),
        blast_radius_score=r.blast_radius_score,
        dependent_control_count=r.dependent_control_count,
    ).model_dump()


def _personnel(r: Personnel) -> dict:
    return PersonnelResponse(
        id=r.id,
        email=r.email,
        full_name=r.full_name,
        department=r.department,
        title=r.title,
        employee_type=r.employee_type,
        hr_status=r.hr_status,
        idp_status=r.idp_status,
        mfa_enabled=r.mfa_enabled,
        training_status=r.training_status,
        risk_score=r.risk_score,
        is_active=r.is_active,
    ).model_dump()


def _data_silo(r: DataSilo) -> dict:
    return DataSiloResponse(
        id=r.id,
        name=r.name,
        silo_type=r.silo_type,
        provider=r.provider,
        data_classification=r.data_classification,
        contains_pii=r.contains_pii,
        contains_phi=r.contains_phi,
        scan_status=r.scan_status,
        owner=r.owner,
        is_active=r.is_active,
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _system_dependency(r: SystemDependency) -> dict:
    return SystemDependencyResponse(
        id=r.id,
        consumer_system_id=r.consumer_system_id,
        provider_system_id=r.provider_system_id,
        dependency_type=r.dependency_type,
        description=r.description,
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _control_inheritance(r: ControlInheritance) -> dict:
    return ControlInheritanceResponse(
        id=r.id,
        system_profile_id=r.system_profile_id,
        framework=r.framework,
        control_id=r.control_id,
        inheritance_type=r.inheritance_type,
        provider_system_id=r.provider_system_id,
        status=r.status,
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _change_event(r: ChangeEvent) -> dict:
    return ChangeEventResponse(
        id=r.id,
        source=r.source,
        source_type=r.source_type,
        event_type=r.event_type,
        actor=r.actor,
        action=r.action,
        resource_id=r.resource_id,
        resource_type=r.resource_type,
        occurred_at=_dt_str(r.occurred_at),
        ingested_at=_dt_str(r.ingested_at),
    ).model_dump()


def _pipeline_run(r: PipelineRun) -> dict:
    return PipelineRunResponse(
        id=r.id,
        status=r.status,
        connectors_succeeded=r.connectors_succeeded,
        connectors_failed=r.connectors_failed,
        raw_events_collected=r.raw_events_collected,
        findings_normalized=r.findings_normalized,
        controls_mapped=r.controls_mapped,
        started_at=_dt_str(r.started_at),
        completed_at=_dt_str(r.completed_at),
        duration_seconds=r.duration_seconds,
        triggered_by=r.triggered_by,
    ).model_dump()


def _saved_query(r: SavedQuery) -> dict:
    return SavedQueryResponse(
        id=r.id,
        name=r.name,
        description=r.description,
        query_type=r.query_type,
        shared=r.shared,
        created_by=r.created_by,
        created_at=_dt_str(r.created_at),
        last_run_at=_dt_str(r.last_run_at),
        run_count=r.run_count,
    ).model_dump()


def _watch_subscription(r: WatchSubscription) -> dict:
    return WatchSubscriptionResponse(
        id=r.id,
        user_id=r.user_id,
        entity_type=r.entity_type,
        entity_id=r.entity_id,
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _escalation_policy(r: EscalationPolicy) -> dict:
    return EscalationPolicyResponse(
        id=r.id,
        name=r.name,
        description=r.description,
        levels=r.levels,
        cooldown_minutes=r.cooldown_minutes,
        active=r.active,
        entity_types=r.entity_types,
        min_severity=r.min_severity,
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _legal_hold(r: LegalHold) -> dict:
    return LegalHoldResponse(
        id=r.id,
        reason=r.reason,
        start_date=_dt_str(r.start_date),
        end_date=_dt_str(r.end_date),
        created_by=r.created_by,
        is_active=r.is_active,
        framework=r.framework,
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _evidence_request(r: EvidenceRequest) -> dict:
    return EvidenceRequestResponse(
        id=r.id,
        engagement_id=r.engagement_id,
        auditor_id=r.auditor_id,
        framework=r.framework,
        control_id=r.control_id,
        description=r.description,
        status=r.status,
        fulfilled_by=r.fulfilled_by,
        fulfilled_at=_dt_str(r.fulfilled_at),
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _questionnaire_template(r: QuestionnaireTemplate) -> dict:
    return QuestionnaireTemplateResponse(
        id=r.id,
        name=r.name,
        template_type=r.template_type,
        version=r.version,
        description=r.description,
        total_questions=r.total_questions,
        is_active=r.is_active,
        created_at=_dt_str(r.created_at),
    ).model_dump()


def _questionnaire(r: Questionnaire) -> dict:
    return QuestionnaireResponse(
        id=r.id,
        template_id=r.template_id,
        vendor_name=r.vendor_name,
        vendor_contact_email=r.vendor_contact_email,
        status=r.status,
        completion_pct=r.completion_pct,
        risk_score=r.risk_score,
        due_date=_dt_str(r.due_date),
        created_at=_dt_str(r.created_at),
    ).model_dump()


# ---------------------------------------------------------------------------
# Helper to fetch a single row by ID or 404
# ---------------------------------------------------------------------------


def _get_or_404(db: Session, model, row_id: str):
    row = db.query(model).filter(model.id == row_id).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"{model.__tablename__} {row_id} not found")
    return row


# ===========================================================================
# Routes
# ===========================================================================


# ---------------------------------------------------------------------------
# 1. Assets
# ---------------------------------------------------------------------------


@router.get("/assets", response_model=PaginatedResponse)
def list_assets(
    resource_type: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if resource_type:
        filters.append(Asset.resource_type == resource_type)
    if status:
        filters.append(Asset.status == status)
    return _paginate(
        db, Asset, _asset, limit, offset, order_col=Asset.last_seen.desc(), filters=filters
    )


@router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _asset(_get_or_404(db, Asset, asset_id))


# ---------------------------------------------------------------------------
# 2. Vendors
# ---------------------------------------------------------------------------


@router.get("/vendors", response_model=PaginatedResponse)
def list_vendors(
    tier: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if tier:
        filters.append(Vendor.tier == tier)
    return _paginate(
        db, Vendor, _vendor, limit, offset, order_col=Vendor.name.asc(), filters=filters
    )


@router.get("/vendors/{vendor_id}", response_model=VendorResponse)
def get_vendor(
    vendor_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _vendor(_get_or_404(db, Vendor, vendor_id))


# ---------------------------------------------------------------------------
# 3. Personnel
# ---------------------------------------------------------------------------


@router.get("/personnel", response_model=PaginatedResponse)
def list_personnel(
    department: str | None = Query(None),
    hr_status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if department:
        filters.append(Personnel.department == department)
    if hr_status:
        filters.append(Personnel.hr_status == hr_status)
    return _paginate(db, Personnel, _personnel, limit, offset, filters=filters)


@router.get("/personnel/{personnel_id}", response_model=PersonnelResponse)
def get_personnel_by_id(
    personnel_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _personnel(_get_or_404(db, Personnel, personnel_id))


# ---------------------------------------------------------------------------
# 4. Data Silos
# ---------------------------------------------------------------------------


@router.get("/data-silos", response_model=PaginatedResponse)
def list_data_silos(
    silo_type: str | None = Query(None),
    provider: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if silo_type:
        filters.append(DataSilo.silo_type == silo_type)
    if provider:
        filters.append(DataSilo.provider == provider)
    return _paginate(db, DataSilo, _data_silo, limit, offset, filters=filters)


@router.get("/data-silos/{silo_id}", response_model=DataSiloResponse)
def get_data_silo(
    silo_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _data_silo(_get_or_404(db, DataSilo, silo_id))


# ---------------------------------------------------------------------------
# 5. System Dependencies
# ---------------------------------------------------------------------------


@router.get("/system-dependencies", response_model=PaginatedResponse)
def list_system_dependencies(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _paginate(db, SystemDependency, _system_dependency, limit, offset)


# ---------------------------------------------------------------------------
# 6. Control Inheritances
# ---------------------------------------------------------------------------


@router.get("/control-inheritances", response_model=PaginatedResponse)
def list_control_inheritances(
    framework: str | None = Query(None),
    inheritance_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if framework:
        filters.append(ControlInheritance.framework == framework)
    if inheritance_type:
        filters.append(ControlInheritance.inheritance_type == inheritance_type)
    return _paginate(db, ControlInheritance, _control_inheritance, limit, offset, filters=filters)


# ---------------------------------------------------------------------------
# 7. Change Events
# ---------------------------------------------------------------------------


@router.get("/change-events", response_model=PaginatedResponse)
def list_change_events(
    source: str | None = Query(None),
    event_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if source:
        filters.append(ChangeEvent.source == source)
    if event_type:
        filters.append(ChangeEvent.event_type == event_type)
    return _paginate(
        db,
        ChangeEvent,
        _change_event,
        limit,
        offset,
        order_col=ChangeEvent.occurred_at.desc(),
        filters=filters,
    )


@router.get("/change-events/{event_id}", response_model=ChangeEventResponse)
def get_change_event(
    event_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _change_event(_get_or_404(db, ChangeEvent, event_id))


# ---------------------------------------------------------------------------
# 8. Pipeline Runs
# ---------------------------------------------------------------------------


@router.get("/pipeline-runs", response_model=PaginatedResponse)
def list_pipeline_runs(
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if status:
        filters.append(PipelineRun.status == status)
    return _paginate(
        db,
        PipelineRun,
        _pipeline_run,
        limit,
        offset,
        order_col=PipelineRun.started_at.desc(),
        filters=filters,
    )


@router.get("/pipeline-runs/{run_id}", response_model=PipelineRunResponse)
def get_pipeline_run(
    run_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _pipeline_run(_get_or_404(db, PipelineRun, run_id))


# ---------------------------------------------------------------------------
# 9. Saved Queries
# ---------------------------------------------------------------------------


@router.get("/saved-queries", response_model=PaginatedResponse)
def list_saved_queries(
    query_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    filters = []
    if query_type:
        filters.append(SavedQuery.query_type == query_type)
    # Show user's own queries plus shared ones
    filters.append(
        (SavedQuery.shared == True) | (SavedQuery.created_by == current_user.email)  # noqa: E712
    )
    return _paginate(db, SavedQuery, _saved_query, limit, offset, filters=filters)


@router.post("/saved-queries", response_model=SavedQueryResponse, status_code=201)
def create_saved_query(
    body: SavedQueryCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    row = SavedQuery(
        name=body.name,
        description=body.description,
        sql_text=body.sql_text,
        query_type=body.query_type,
        parameters=body.parameters or {},
        shared=body.shared,
        created_by=current_user.email,
    )
    db.add(row)
    db.flush()
    return _saved_query(row)


@router.delete("/saved-queries/{query_id}", status_code=204)
def delete_saved_query(
    query_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    row = _get_or_404(db, SavedQuery, query_id)
    if row.created_by != current_user.email:
        raise HTTPException(status_code=403, detail="Can only delete your own saved queries")
    db.delete(row)
    db.flush()


# ---------------------------------------------------------------------------
# 10. Watch Subscriptions
# ---------------------------------------------------------------------------


@router.get("/watch-subscriptions", response_model=PaginatedResponse)
def list_watch_subscriptions(
    entity_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    filters = [WatchSubscription.user_id == current_user.id]
    if entity_type:
        filters.append(WatchSubscription.entity_type == entity_type)
    return _paginate(db, WatchSubscription, _watch_subscription, limit, offset, filters=filters)


@router.post("/watch-subscriptions", response_model=WatchSubscriptionResponse, status_code=201)
def create_watch_subscription(
    body: WatchSubscriptionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    row = WatchSubscription(
        user_id=current_user.id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
    )
    db.add(row)
    db.flush()
    return _watch_subscription(row)


@router.delete("/watch-subscriptions/{sub_id}", status_code=204)
def delete_watch_subscription(
    sub_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    row = _get_or_404(db, WatchSubscription, sub_id)
    if row.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Can only delete your own subscriptions")
    db.delete(row)
    db.flush()


# ---------------------------------------------------------------------------
# 11. Escalation Policies
# ---------------------------------------------------------------------------


@router.get("/escalation-policies", response_model=PaginatedResponse)
def list_escalation_policies(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _paginate(db, EscalationPolicy, _escalation_policy, limit, offset)


@router.get("/escalation-policies/{policy_id}", response_model=EscalationPolicyResponse)
def get_escalation_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _escalation_policy(_get_or_404(db, EscalationPolicy, policy_id))


# ---------------------------------------------------------------------------
# 12. Legal Holds
# ---------------------------------------------------------------------------


@router.get("/legal-holds", response_model=PaginatedResponse)
def list_legal_holds(
    is_active: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if is_active is not None:
        filters.append(LegalHold.is_active == is_active)  # noqa: E712
    return _paginate(db, LegalHold, _legal_hold, limit, offset, filters=filters)


@router.get("/legal-holds/{hold_id}", response_model=LegalHoldResponse)
def get_legal_hold(
    hold_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _legal_hold(_get_or_404(db, LegalHold, hold_id))


# ---------------------------------------------------------------------------
# 13. Evidence Requests
# ---------------------------------------------------------------------------


@router.get("/evidence-requests", response_model=PaginatedResponse)
def list_evidence_requests(
    engagement_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if engagement_id:
        filters.append(EvidenceRequest.engagement_id == engagement_id)
    if status:
        filters.append(EvidenceRequest.status == status)
    return _paginate(db, EvidenceRequest, _evidence_request, limit, offset, filters=filters)


@router.post("/evidence-requests", response_model=EvidenceRequestResponse, status_code=201)
def create_evidence_request(
    body: EvidenceRequestCreateRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("write")),
):
    row = EvidenceRequest(
        engagement_id=body.engagement_id,
        auditor_id=body.auditor_id,
        framework=body.framework,
        control_id=body.control_id,
        description=body.description,
    )
    db.add(row)
    db.flush()
    return _evidence_request(row)


# ---------------------------------------------------------------------------
# 14. Questionnaire Templates
# ---------------------------------------------------------------------------


@router.get("/questionnaire-templates", response_model=PaginatedResponse)
def list_questionnaire_templates(
    template_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if template_type:
        filters.append(QuestionnaireTemplate.template_type == template_type)
    return _paginate(
        db,
        QuestionnaireTemplate,
        _questionnaire_template,
        limit,
        offset,
        filters=filters,
    )


# ---------------------------------------------------------------------------
# 15. Questionnaires
# ---------------------------------------------------------------------------


@router.get("/questionnaires", response_model=PaginatedResponse)
def list_questionnaires(
    status: str | None = Query(None),
    vendor_name: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    filters = []
    if status:
        filters.append(Questionnaire.status == status)
    if vendor_name:
        filters.append(Questionnaire.vendor_name == vendor_name)
    return _paginate(db, Questionnaire, _questionnaire, limit, offset, filters=filters)


@router.get("/questionnaires/{questionnaire_id}", response_model=QuestionnaireResponse)
def get_questionnaire(
    questionnaire_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_permission("read")),
):
    return _questionnaire(_get_or_404(db, Questionnaire, questionnaire_id))
