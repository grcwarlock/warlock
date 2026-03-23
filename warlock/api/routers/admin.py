"""Admin routes: users, systems, personnel, retention, data silos, tools, audit trail, GDPR."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.auth import PERMISSIONS
from warlock.api.deps import get_db, require_permission, apply_source_scope
from warlock.api.routers.schemas import (
    MessageResponse,
    PaginatedResponse,
    _dt_str,
    _escape_like,
    _parse_dt,
)
from warlock.db.models import DataSilo, Personnel, SystemProfile, User
from warlock.db.repository import get_repos

router = APIRouter()
log = logging.getLogger(__name__)


# Alert config key for shared cache (survives across workers when Redis is configured)
_ALERT_CONFIG_KEY = "alert_config"
_ALERT_CONFIG_TTL = 86400  # 24 hours


# ---------------------------------------------------------------------------
# Models — Users (re-used from auth for admin endpoints)
# ---------------------------------------------------------------------------


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    allowed_frameworks: list[str]
    allowed_sources: list[str]
    created_at: str
    last_login: str | None

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    allowed_frameworks: list[str] | None = None
    allowed_sources: list[str] | None = None


# ---------------------------------------------------------------------------
# Models — Systems
# ---------------------------------------------------------------------------


class SystemProfileCreateRequest(BaseModel):
    name: str
    description: str | None = None
    acronym: str | None = None
    confidentiality_impact: str = "moderate"
    integrity_impact: str = "moderate"
    availability_impact: str = "moderate"
    overall_impact: str = "moderate"
    cloud_accounts: list[dict[str, Any]] = Field(default_factory=list)
    network_boundaries: list[dict[str, Any]] = Field(default_factory=list)
    interconnections: list[dict[str, Any]] = Field(default_factory=list)
    connector_scope: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    system_owner: str | None = None
    system_owner_email: str | None = None
    isso: str | None = None
    isso_email: str | None = None
    issm: str | None = None
    issm_email: str | None = None
    authorizing_official: str | None = None
    ao_email: str | None = None
    authorization_status: str = "not_authorized"
    deployment_model: str | None = None
    service_model: str | None = None


class SystemProfileUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    acronym: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    overall_impact: str | None = None
    cloud_accounts: list[dict[str, Any]] | None = None
    network_boundaries: list[dict[str, Any]] | None = None
    interconnections: list[dict[str, Any]] | None = None
    connector_scope: list[str] | None = None
    frameworks: list[str] | None = None
    system_owner: str | None = None
    system_owner_email: str | None = None
    isso: str | None = None
    isso_email: str | None = None
    issm: str | None = None
    issm_email: str | None = None
    authorizing_official: str | None = None
    ao_email: str | None = None
    authorization_status: str | None = None
    authorization_date: str | None = None
    authorization_expiry: str | None = None
    continuous_monitoring_plan: str | None = None
    deployment_model: str | None = None
    service_model: str | None = None


class SystemProfileResponse(BaseModel):
    id: str
    name: str
    acronym: str | None = None
    description: str | None = None
    confidentiality_impact: str | None = None
    integrity_impact: str | None = None
    availability_impact: str | None = None
    overall_impact: str | None = None
    cloud_accounts: list[dict[str, Any]] | None = None
    network_boundaries: list[dict[str, Any]] | None = None
    interconnections: list[dict[str, Any]] | None = None
    connector_scope: list[str] | None = None
    frameworks: list[str] | None = None
    system_owner: str | None = None
    system_owner_email: str | None = None
    isso: str | None = None
    isso_email: str | None = None
    issm: str | None = None
    issm_email: str | None = None
    authorizing_official: str | None = None
    ao_email: str | None = None
    authorization_status: str | None = None
    authorization_date: str | None = None
    authorization_expiry: str | None = None
    continuous_monitoring_plan: str | None = None
    deployment_model: str | None = None
    service_model: str | None = None
    is_active: bool
    created_at: str
    updated_at: str | None = None

    model_config = {"from_attributes": True}


class SystemPostureResponse(BaseModel):
    framework: str
    total: int
    compliant: int
    non_compliant: int
    partial: int
    not_assessed: int
    posture_score: float


# ---------------------------------------------------------------------------
# Models — Personnel
# ---------------------------------------------------------------------------


class PersonnelResponse(BaseModel):
    id: str
    email: str
    full_name: str
    department: str | None = None
    title: str | None = None
    manager_email: str | None = None
    employee_type: str | None = None
    hr_employee_id: str | None = None
    hire_date: str | None = None
    termination_date: str | None = None
    hr_status: str | None = None
    background_check_status: str | None = None
    idp_provider: str | None = None
    idp_status: str | None = None
    idp_last_login: str | None = None
    mfa_enabled: bool | None = None
    idp_groups: list[str] | None = None
    training_status: str | None = None
    last_training_date: str | None = None
    phishing_score: float | None = None
    last_access_review: str | None = None
    access_review_status: str | None = None
    flags: list[str] | None = None
    risk_score: float = 0.0
    is_active: bool = True
    last_synced: str | None = None
    created_at: str

    model_config = {"from_attributes": True}


class PersonnelSummaryResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    by_department: dict[str, int]
    flagged: int
    terminated_with_active_access: int
    no_mfa: int


class PersonnelSyncResponse(BaseModel):
    hr: dict[str, int] | None = None
    idp: dict[str, int] | None = None
    training: dict[str, int] | None = None
    total_personnel: int = 0


# ---------------------------------------------------------------------------
# Models — Retention
# ---------------------------------------------------------------------------


class RetentionReportResponse(BaseModel):
    total_raw_events: int
    age_buckets: dict[str, int]
    purgeable: dict[str, int]
    active_holds: list[dict[str, Any]]
    active_hold_count: int
    framework_retention: dict[str, int]


class PurgeRequest(BaseModel):
    dry_run: bool = True
    framework: str | None = None


class LegalHoldCreateRequest(BaseModel):
    reason: str
    start_date: str
    end_date: str | None = None


class LegalHoldResponse(BaseModel):
    id: str
    reason: str
    start_date: str | None
    end_date: str | None
    created_by: str | None
    is_active: bool
    created_at: str | None


# ---------------------------------------------------------------------------
# Models — Data Silos
# ---------------------------------------------------------------------------


class DataSiloCreateRequest(BaseModel):
    name: str
    silo_type: str
    provider: str | None = None
    location: str | None = None
    data_classification: str = "unknown"
    contains_pii: bool = False
    contains_phi: bool = False
    contains_pci: bool = False
    owner: str | None = None
    team: str | None = None


class DataSiloUpdateRequest(BaseModel):
    data_classification: str | None = None
    contains_pii: bool | None = None
    contains_phi: bool | None = None
    contains_pci: bool | None = None
    contains_credentials: bool | None = None
    encrypted_at_rest: bool | None = None
    encrypted_in_transit: bool | None = None
    access_logging_enabled: bool | None = None
    backup_enabled: bool | None = None
    owner: str | None = None
    team: str | None = None
    remediation_status: str | None = None
    remediation_notes: str | None = None


class DataSiloResponse(BaseModel):
    id: str
    name: str
    silo_type: str
    provider: str | None = None
    location: str | None = None
    data_classification: str = "unknown"
    contains_pii: bool = False
    contains_phi: bool = False
    contains_pci: bool = False
    contains_credentials: bool = False
    last_scan_date: str | None = None
    scan_status: str | None = None
    sensitive_field_count: int = 0
    total_records: int | None = None
    scan_findings: list[dict[str, Any]] | None = None
    encrypted_at_rest: bool | None = None
    encrypted_in_transit: bool | None = None
    access_logging_enabled: bool | None = None
    backup_enabled: bool | None = None
    retention_days: int | None = None
    owner: str | None = None
    team: str | None = None
    applicable_frameworks: list[str] | None = None
    remediation_status: str | None = None
    remediation_notes: str | None = None
    is_active: bool = True
    created_at: str
    updated_at: str | None = None

    model_config = {"from_attributes": True}


class DataSiloSummaryResponse(BaseModel):
    total: int
    by_type: dict[str, int]
    by_classification: dict[str, int]
    by_provider: dict[str, int]
    pii_count: int
    phi_count: int
    pci_count: int
    unprotected: int
    unclassified: int


# ---------------------------------------------------------------------------
# Models — Audit Trail
# ---------------------------------------------------------------------------


class AuditEntryResponse(BaseModel):
    id: str
    sequence: float
    action: str
    entity_type: str
    entity_id: str
    actor: str
    entry_hash: str
    previous_hash: str
    created_at: str

    model_config = {"from_attributes": True}


class AuditVerifyResponse(BaseModel):
    valid: bool
    total_entries: int
    errors: list[str]


# ---------------------------------------------------------------------------
# Models — Alerts
# ---------------------------------------------------------------------------


class AlertConfigResponse(BaseModel):
    alert_rules: list[dict[str, Any]]


class AlertConfigUpdateRequest(BaseModel):
    alert_rules: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_to_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        is_active=user.is_active,
        allowed_frameworks=user.allowed_frameworks or [],
        allowed_sources=user.allowed_sources or [],
        created_at=_dt_str(user.created_at) or "",
        last_login=_dt_str(user.last_login),
    )


def _system_profile_to_response(sp: SystemProfile) -> SystemProfileResponse:
    return SystemProfileResponse(
        id=sp.id,
        name=sp.name,
        acronym=sp.acronym,
        description=sp.description,
        confidentiality_impact=sp.confidentiality_impact,
        integrity_impact=sp.integrity_impact,
        availability_impact=sp.availability_impact,
        overall_impact=sp.overall_impact,
        cloud_accounts=sp.cloud_accounts,
        network_boundaries=sp.network_boundaries,
        interconnections=sp.interconnections,
        connector_scope=sp.connector_scope,
        frameworks=sp.frameworks,
        system_owner=sp.system_owner,
        system_owner_email=sp.system_owner_email,
        isso=sp.isso,
        isso_email=sp.isso_email,
        issm=sp.issm,
        issm_email=sp.issm_email,
        authorizing_official=sp.authorizing_official,
        ao_email=sp.ao_email,
        authorization_status=sp.authorization_status,
        authorization_date=_dt_str(sp.authorization_date),
        authorization_expiry=_dt_str(sp.authorization_expiry),
        continuous_monitoring_plan=sp.continuous_monitoring_plan,
        deployment_model=sp.deployment_model,
        service_model=sp.service_model,
        is_active=sp.is_active or False,
        created_at=_dt_str(sp.created_at) or "",
        updated_at=_dt_str(sp.updated_at),
    )


def _personnel_to_response(p: Personnel) -> PersonnelResponse:
    return PersonnelResponse(
        id=p.id,
        email=p.email,
        full_name=p.full_name,
        department=p.department,
        title=p.title,
        manager_email=p.manager_email,
        employee_type=p.employee_type,
        hr_employee_id=p.hr_employee_id,
        hire_date=_dt_str(p.hire_date),
        termination_date=_dt_str(p.termination_date),
        hr_status=p.hr_status,
        background_check_status=p.background_check_status,
        idp_provider=p.idp_provider,
        idp_status=p.idp_status,
        idp_last_login=_dt_str(p.idp_last_login),
        mfa_enabled=p.mfa_enabled,
        idp_groups=p.idp_groups,
        training_status=p.training_status,
        last_training_date=_dt_str(p.last_training_date),
        phishing_score=p.phishing_score,
        last_access_review=_dt_str(p.last_access_review),
        access_review_status=p.access_review_status,
        flags=p.flags or [],
        risk_score=p.risk_score or 0.0,
        is_active=p.is_active or True,
        last_synced=_dt_str(p.last_synced),
        created_at=_dt_str(p.created_at) or "",
    )


def _data_silo_to_response(s: DataSilo) -> DataSiloResponse:
    return DataSiloResponse(
        id=s.id,
        name=s.name,
        silo_type=s.silo_type,
        provider=s.provider,
        location=s.location,
        data_classification=s.data_classification or "unknown",
        contains_pii=s.contains_pii or False,
        contains_phi=s.contains_phi or False,
        contains_pci=s.contains_pci or False,
        contains_credentials=s.contains_credentials or False,
        last_scan_date=_dt_str(s.last_scan_date),
        scan_status=s.scan_status,
        sensitive_field_count=s.sensitive_field_count or 0,
        total_records=s.total_records,
        scan_findings=s.scan_findings,
        encrypted_at_rest=s.encrypted_at_rest,
        encrypted_in_transit=s.encrypted_in_transit,
        access_logging_enabled=s.access_logging_enabled,
        backup_enabled=s.backup_enabled,
        retention_days=s.retention_days,
        owner=s.owner,
        team=s.team,
        applicable_frameworks=s.applicable_frameworks,
        remediation_status=s.remediation_status,
        remediation_notes=s.remediation_notes,
        is_active=s.is_active or True,
        created_at=_dt_str(s.created_at) or "",
        updated_at=_dt_str(s.updated_at),
    )


# ---------------------------------------------------------------------------
# Routes — Users (admin)
# ---------------------------------------------------------------------------


@router.get("/users", response_model=list[UserResponse])
def list_users(
    role: str | None = Query(None),
    is_active: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    repos = get_repos(db)
    rows = repos.users.list_filtered(role=role, is_active=is_active, limit=limit, offset=offset)
    return [_user_to_response(u) for u in rows]


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    repos = get_repos(db)
    user = repos.users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    body: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    repos = get_repos(db)
    user = repos.users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.name is not None:
        user.name = body.name
    if body.role is not None:
        if body.role not in PERMISSIONS:
            raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.allowed_frameworks is not None:
        user.allowed_frameworks = body.allowed_frameworks
    if body.allowed_sources is not None:
        user.allowed_sources = body.allowed_sources
    db.flush()
    return _user_to_response(user)


@router.delete("/users/{user_id}", response_model=MessageResponse)
def deactivate_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    repos = get_repos(db)
    user = repos.users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    user.is_active = False
    # S-4: Revoke all tokens by setting token_valid_after to now
    user.token_valid_after = datetime.now(timezone.utc)
    # S-4: Deactivate all associated API keys
    repos.users.deactivate_api_keys(user_id)
    log.info(
        "User %s deactivated: tokens revoked, %s API keys deactivated", user.email, user_id[:8]
    )
    return MessageResponse(message="User deactivated")


# ---------------------------------------------------------------------------
# Routes — Systems
# ---------------------------------------------------------------------------


@router.get("/systems", response_model=list[SystemProfileResponse])
def list_systems(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    # C-7: Apply ABAC framework scope filter
    from warlock.workflows.system_profile import SystemProfileManager

    mgr = SystemProfileManager()
    profiles = mgr.list_active(db)
    # Filter by user's allowed frameworks (list-based, not query-based)
    if current_user.allowed_frameworks:
        allowed = set(current_user.allowed_frameworks)
        profiles = [
            sp
            for sp in profiles
            if not sp.frameworks or any(f in allowed for f in (sp.frameworks or []))
        ]
    return [_system_profile_to_response(sp) for sp in profiles[offset : offset + limit]]


@router.post("/systems", response_model=SystemProfileResponse, status_code=201)
def create_system(
    body: SystemProfileCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.system_profile import SystemProfileManager

    mgr = SystemProfileManager()
    kwargs = body.model_dump(exclude={"name", "description"}, exclude_none=True)
    try:
        sp = mgr.create(db, name=body.name, description=body.description or "", **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _system_profile_to_response(sp)


@router.get("/systems/expiring", response_model=list[SystemProfileResponse])
def expiring_systems(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.system_profile import SystemProfileManager

    mgr = SystemProfileManager()
    profiles = mgr.check_authorization_expiry(db)
    return [_system_profile_to_response(sp) for sp in profiles]


@router.get("/systems/{system_id}", response_model=SystemProfileResponse)
def get_system(
    system_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    sp = repos.system_profiles.get(system_id)
    if not sp:
        raise HTTPException(status_code=404, detail="System profile not found")
    return _system_profile_to_response(sp)


@router.patch("/systems/{system_id}", response_model=SystemProfileResponse)
def update_system(
    system_id: str,
    body: SystemProfileUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.system_profile import SystemProfileManager

    mgr = SystemProfileManager()
    kwargs = body.model_dump(exclude_none=True)
    # Convert date strings to datetimes
    if "authorization_date" in kwargs:
        kwargs["authorization_date"] = _parse_dt(kwargs["authorization_date"])
    if "authorization_expiry" in kwargs:
        kwargs["authorization_expiry"] = _parse_dt(kwargs["authorization_expiry"])
    try:
        sp = mgr.update(db, system_id, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _system_profile_to_response(sp)


@router.delete("/systems/{system_id}", response_model=MessageResponse)
def archive_system(
    system_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("delete")),
):
    repos = get_repos(db)
    sp = repos.system_profiles.get(system_id)
    if not sp:
        raise HTTPException(status_code=404, detail="System profile not found")
    sp.is_active = False
    sp.updated_at = datetime.now(timezone.utc)
    db.flush()
    return MessageResponse(message="System profile archived")


@router.get("/systems/{system_id}/findings")
def system_findings(
    system_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.system_profile import SystemProfileManager

    mgr = SystemProfileManager()
    try:
        findings = mgr.scope_findings(db, system_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return [
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
        for f in findings
    ]


@router.get("/systems/{system_id}/posture", response_model=SystemPostureResponse)
def system_posture(
    system_id: str,
    framework: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.system_profile import SystemProfileManager

    mgr = SystemProfileManager()
    try:
        posture = mgr.posture_for_system(db, system_id, framework)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return SystemPostureResponse(**posture)


@router.get("/systems/{system_id}/ssp-header")
def system_ssp_header(
    system_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.system_profile import SystemProfileManager

    mgr = SystemProfileManager()
    sp = mgr.get(db, system_id)
    if not sp:
        raise HTTPException(status_code=404, detail="System profile not found")
    return mgr.generate_ssp_header(sp)


# ---------------------------------------------------------------------------
# Routes — Personnel
# ---------------------------------------------------------------------------


@router.get("/personnel", response_model=PaginatedResponse)
def list_personnel(
    department: str | None = Query(None),
    hr_status: str | None = Query(None, alias="status"),
    has_flags: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    rows, total = repos.personnel.list_filtered(
        department=department,
        hr_status=hr_status,
        has_flags=has_flags,
        limit=limit,
        offset=offset,
    )
    items = [_personnel_to_response(p) for p in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/personnel/flags", response_model=list[PersonnelResponse])
def personnel_flags(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    rows = repos.personnel.flagged(limit=limit)
    return [_personnel_to_response(p) for p in rows]


@router.get("/personnel/terminated-active", response_model=list[PersonnelResponse])
def personnel_terminated_active(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.personnel import PersonnelManager

    mgr = PersonnelManager()
    rows = mgr.terminated_with_active_access(db)
    return [_personnel_to_response(p) for p in rows]


@router.get("/personnel/summary", response_model=PersonnelSummaryResponse)
def personnel_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.personnel import PersonnelManager

    mgr = PersonnelManager()
    return PersonnelSummaryResponse(**mgr.summary(db))


@router.post("/personnel/sync", response_model=PersonnelSyncResponse)
def personnel_sync(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.personnel import PersonnelManager

    mgr = PersonnelManager()
    result = mgr.sync_all(db)
    return PersonnelSyncResponse(**result)


@router.get("/personnel/{personnel_id}", response_model=PersonnelResponse)
def get_personnel(
    personnel_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    p = repos.personnel.get(personnel_id)
    if not p:
        raise HTTPException(status_code=404, detail="Personnel record not found")
    return _personnel_to_response(p)


# ---------------------------------------------------------------------------
# Routes — Retention & Legal Holds
# ---------------------------------------------------------------------------


@router.get("/retention/report", response_model=RetentionReportResponse)
def retention_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.retention import RetentionManager

    mgr = RetentionManager()
    report = mgr.retention_report(db)
    return RetentionReportResponse(**report)


@router.post("/retention/purge")
def retention_purge(
    body: PurgeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("delete")),
):
    from warlock.workflows.retention import RetentionManager

    mgr = RetentionManager()
    result = mgr.purge_expired(db, dry_run=body.dry_run, framework=body.framework)
    return result


@router.post("/retention/legal-hold", response_model=LegalHoldResponse, status_code=201)
def create_legal_hold(
    body: LegalHoldCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.retention import RetentionManager

    mgr = RetentionManager()
    repos = get_repos(db)
    hold_id = mgr.set_legal_hold(
        db,
        reason=body.reason,
        start_date=body.start_date,
        end_date=body.end_date,
        actor=current_user.email,
    )
    hold = repos.legal_holds.get(hold_id)
    return LegalHoldResponse(
        id=hold.id,
        reason=hold.reason,
        start_date=_dt_str(hold.start_date),
        end_date=_dt_str(hold.end_date),
        created_by=hold.created_by,
        is_active=hold.is_active,
        created_at=_dt_str(hold.created_at),
    )


@router.get("/retention/legal-holds", response_model=list[LegalHoldResponse])
def list_legal_holds(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.retention import RetentionManager

    mgr = RetentionManager()
    holds = mgr.active_holds(db)
    return [
        LegalHoldResponse(
            id=h["id"],
            reason=h["reason"],
            start_date=h["start_date"],
            end_date=h["end_date"],
            created_by=h["created_by"],
            is_active=h["is_active"],
            created_at=h["created_at"],
        )
        for h in holds
    ]


@router.delete("/retention/legal-holds/{hold_id}", response_model=MessageResponse)
def remove_legal_hold(
    hold_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.retention import RetentionManager

    mgr = RetentionManager()
    removed = mgr.remove_legal_hold(db, hold_id, actor=current_user.email)
    if not removed:
        raise HTTPException(status_code=404, detail="Legal hold not found")
    return MessageResponse(message="Legal hold removed")


# ---------------------------------------------------------------------------
# Routes — Tools
# ---------------------------------------------------------------------------


@router.get("/tools", response_model=list[dict[str, Any]])
def list_tools(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    from warlock.workflows.tool_config import ToolConfigManager

    mgr = ToolConfigManager()
    connectors = mgr.list_connectors()
    return connectors[offset : offset + limit]


@router.post("/tools/{provider}/test")
def test_tool(
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager

    mgr = ToolConfigManager()
    return mgr.test_connector(db, provider)


@router.post("/tools/test-all")
def test_all_tools(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager

    mgr = ToolConfigManager()
    return mgr.test_all(db)


@router.get("/tools/{provider}/env-vars")
def tool_env_vars(
    provider: str,
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager

    mgr = ToolConfigManager()
    return mgr.get_required_env_vars(provider)


@router.get("/tools/{provider}/history")
def tool_history(
    provider: str,
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager

    mgr = ToolConfigManager()
    return mgr.connection_history(db, provider, limit=limit)


# ---------------------------------------------------------------------------
# Routes — Audit Trail
# ---------------------------------------------------------------------------


@router.get("/audit-trail", response_model=PaginatedResponse)
def list_audit_trail(
    action: str | None = Query(None),
    entity_type: str | None = Query(None),
    entity_id: str | None = Query(None),
    actor: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    repos = get_repos(db)
    rows, total = repos.audit_entries.list_filtered(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        date_from=_parse_dt(date_from) if date_from else None,
        date_to=_parse_dt(date_to) if date_to else None,
        escape_like_fn=_escape_like,
        limit=limit,
        offset=offset,
    )

    items = [
        AuditEntryResponse(
            id=e.id,
            sequence=e.sequence,
            action=e.action,
            entity_type=e.entity_type,
            entity_id=e.entity_id,
            actor=e.actor,
            entry_hash=e.entry_hash,
            previous_hash=e.previous_hash,
            created_at=_dt_str(e.created_at) or "",
        )
        for e in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/audit-trail/verify", response_model=AuditVerifyResponse)
def verify_audit_trail(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    from warlock.db.audit import AuditTrail

    repos = get_repos(db)
    trail = AuditTrail(db)
    valid, errors = trail.verify_chain()
    total = repos.audit_entries.total_count()
    return AuditVerifyResponse(valid=valid, total_entries=total, errors=errors)


# ---------------------------------------------------------------------------
# Routes — Alerts
# ---------------------------------------------------------------------------


@router.get("/alerts/config", response_model=AlertConfigResponse)
def get_alert_config(
    current_user: User = Depends(require_permission("read")),
):
    from warlock.utils.cache import get_cache

    config = get_cache().get(_ALERT_CONFIG_KEY) or {"alert_rules": []}
    return AlertConfigResponse(alert_rules=config.get("alert_rules", []))


@router.put("/alerts/config", response_model=AlertConfigResponse)
def update_alert_config(
    body: AlertConfigUpdateRequest,
    current_user: User = Depends(require_permission("write")),
):
    from warlock.utils.cache import get_cache

    config = {"alert_rules": body.alert_rules}
    get_cache().set(_ALERT_CONFIG_KEY, config, ttl=_ALERT_CONFIG_TTL)
    return AlertConfigResponse(alert_rules=config["alert_rules"])


# ---------------------------------------------------------------------------
# Routes — Data Silos
# ---------------------------------------------------------------------------


@router.get("/data-silos", response_model=PaginatedResponse)
def list_data_silos(
    silo_type: str | None = Query(None, alias="type"),
    classification: str | None = Query(None),
    provider: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    # S-1: Apply ABAC scope filters via repository
    scope_fn = lambda q, m: apply_source_scope(q, m, current_user)  # noqa: E731
    rows, total = repos.data_silos.list_filtered(
        scope_filter=scope_fn,
        silo_type=silo_type,
        classification=classification,
        provider=provider,
        limit=limit,
        offset=offset,
    )
    items = [_data_silo_to_response(s) for s in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/data-silos", response_model=DataSiloResponse, status_code=201)
def create_data_silo(
    body: DataSiloCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    now = datetime.now(timezone.utc)
    silo = DataSilo(
        name=body.name,
        silo_type=body.silo_type,
        provider=body.provider,
        location=body.location,
        data_classification=body.data_classification,
        contains_pii=body.contains_pii,
        contains_phi=body.contains_phi,
        contains_pci=body.contains_pci,
        owner=body.owner,
        team=body.team,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.add(silo)
    db.flush()
    return _data_silo_to_response(silo)


@router.get("/data-silos/unclassified", response_model=list[DataSiloResponse])
def unclassified_data_silos(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.data_silos import DataSiloManager

    mgr = DataSiloManager()
    rows = mgr.unclassified(db)
    return [_data_silo_to_response(s) for s in rows]


@router.get("/data-silos/unprotected", response_model=list[DataSiloResponse])
def unprotected_data_silos(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.data_silos import DataSiloManager

    mgr = DataSiloManager()
    rows = mgr.unprotected(db)
    return [_data_silo_to_response(s) for s in rows]


@router.get("/data-silos/summary", response_model=DataSiloSummaryResponse)
def data_silo_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.data_silos import DataSiloManager

    mgr = DataSiloManager()
    return DataSiloSummaryResponse(**mgr.summary(db))


@router.post("/data-silos/discover", response_model=MessageResponse)
def discover_data_silos(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.data_silos import DataSiloManager

    mgr = DataSiloManager()
    result = mgr.discover_from_findings(db)
    return MessageResponse(
        message=f"Discovery complete: {result['created']} created, "
        f"{result['updated']} updated, {result['total']} total"
    )


@router.get("/data-silos/{silo_id}", response_model=DataSiloResponse)
def get_data_silo(
    silo_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    repos = get_repos(db)
    s = repos.data_silos.get(silo_id)
    if not s:
        raise HTTPException(status_code=404, detail="Data silo not found")
    return _data_silo_to_response(s)


@router.patch("/data-silos/{silo_id}", response_model=DataSiloResponse)
def update_data_silo(
    silo_id: str,
    body: DataSiloUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    repos = get_repos(db)
    silo = repos.data_silos.get(silo_id)
    if not silo:
        raise HTTPException(status_code=404, detail="Data silo not found")

    update_data = body.model_dump(exclude_none=True)
    for key, value in update_data.items():
        if hasattr(silo, key):
            setattr(silo, key, value)

    # If classification changed, use the manager to auto-assign frameworks
    if body.data_classification is not None or any(
        k in update_data for k in ("contains_pii", "contains_phi", "contains_pci")
    ):
        from warlock.workflows.data_silos import DataSiloManager

        mgr = DataSiloManager()
        mgr.classify_silo(
            db,
            silo_id,
            classification=silo.data_classification or "unknown",
            contains_pii=silo.contains_pii,
            contains_phi=silo.contains_phi,
            contains_pci=silo.contains_pci,
        )
    else:
        silo.updated_at = datetime.now(timezone.utc)
        db.flush()

    return _data_silo_to_response(silo)


# ---------------------------------------------------------------------------
# Routes — GDPR
# ---------------------------------------------------------------------------


@router.get("/gdpr/export")
def gdpr_export(
    email: str = Query(..., description="Email of the data subject"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    """Export all personal data for a data subject (GDPR Article 15)."""
    from warlock.workflows.gdpr import GDPRManager

    manager = GDPRManager()
    return manager.export_subject_data(db, email)


@router.delete("/gdpr/erase")
def gdpr_erase(
    email: str = Query(..., description="Email of the data subject to anonymize"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    """Anonymize all PII for a data subject (GDPR Article 17).

    Does not delete records -- anonymizes PII fields to preserve
    referential integrity and audit trail.
    """
    from warlock.workflows.gdpr import GDPRManager

    manager = GDPRManager()
    result = manager.erase_subject_data(db, email, erased_by=current_user.email)
    return result
