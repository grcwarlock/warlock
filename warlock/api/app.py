"""Warlock GRC REST API.

Endpoints:
- /api/v1/health                        -- health check
- /api/v1/auth/login                    -- get JWT token
- /api/v1/auth/register                 -- create user (admin only)
- /api/v1/auth/api-keys                 -- manage API keys
- /api/v1/pipeline/collect              -- trigger pipeline run
- /api/v1/pipeline/status               -- pipeline run status
- /api/v1/frameworks                    -- list frameworks
- /api/v1/frameworks/{id}/controls      -- list controls
- /api/v1/findings                      -- list/filter findings
- /api/v1/findings/{id}                 -- finding detail
- /api/v1/results                       -- list/filter control results
- /api/v1/results/coverage              -- coverage summary
- /api/v1/results/posture               -- posture scores
- /api/v1/connectors                    -- list connectors
- /api/v1/connectors/{provider}/status  -- connector health
- /api/v1/export/oscal                  -- export OSCAL (AR, SSP, POA&M)
- /api/v1/engagements                   -- audit engagement CRUD
- /api/v1/engagements/{id}/evidence     -- evidence for audit period
- /api/v1/audit-trail                   -- audit log entries
- /api/v1/audit-trail/verify            -- verify chain integrity
- /api/v1/alerts/config                 -- alert routing config
- /api/v1/users                         -- user management (admin)
"""

from __future__ import annotations

import json
import logging
import os
import re as _re
import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.api.auth import (
    authenticate_user,
    create_access_token,
    create_user,
    generate_api_key,
    hash_password,
    has_permission,
    PERMISSIONS,
)
from warlock.api.deps import get_current_user, get_db, require_permission
from warlock.db.models import (
    APIKey,
    Attestation,
    AuditComment,
    AuditEngagement,
    AuditEntry,
    ConnectorRun,
    ControlMapping,
    ControlResult,
    Finding,
    Issue,
    IssueComment,
    PostureSnapshot,
    RawEvent,
    RiskAnalysis,
    SystemProfile,
    User,
)
from warlock.db.repository import get_repos

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "2.0.0a1"
    timestamp: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    role: str


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    name: str
    password: str
    role: str = "viewer"


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


class APIKeyCreateRequest(BaseModel):
    name: str
    scopes: list[str] = Field(default_factory=list)
    expires_days: int | None = None


class APIKeyResponse(BaseModel):
    id: str
    name: str
    scopes: list[str]
    is_active: bool
    created_at: str
    last_used: str | None
    raw_key: str | None = None  # only returned on creation

    model_config = {"from_attributes": True}


class PipelineStatusResponse(BaseModel):
    running: bool
    last_run_id: str | None = None
    last_status: str | None = None
    last_started: str | None = None
    last_completed: str | None = None
    raw_events: int = 0
    findings: int = 0
    results: int = 0


class PipelineCollectResponse(BaseModel):
    message: str
    run_id: str | None = None


class FrameworkResponse(BaseModel):
    name: str
    control_count: int


class ControlResponse(BaseModel):
    framework: str
    control_id: str
    control_family: str | None
    result_count: int


class FindingResponse(BaseModel):
    id: str
    title: str
    observation_type: str
    severity: str
    resource_id: str | None
    resource_type: str | None
    source: str
    provider: str
    observed_at: str
    detail: Any | None = None

    model_config = {"from_attributes": True}


class ControlResultResponse(BaseModel):
    id: str
    framework: str
    control_id: str
    status: str
    severity: str
    assessor: str
    assertion_name: str | None
    assertion_passed: bool | None
    assessed_at: str
    finding_id: str
    remediation_summary: str | None = None

    model_config = {"from_attributes": True}


class CoverageResponse(BaseModel):
    framework: str
    total: int
    compliant: int
    non_compliant: int
    partial: int
    not_assessed: int
    rate: float


class PostureResponse(BaseModel):
    framework: str
    control_id: str
    status: str
    posture_score: float
    sufficiency_score: float
    evidence_sources: list[str]
    evidence_freshness: float | None

    model_config = {"from_attributes": True}


class ConnectorResponse(BaseModel):
    provider: str
    source_type: str
    enabled: bool
    last_run: str | None
    last_status: str | None


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
    findings: list[FindingResponse]
    results: list[ControlResultResponse]


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


class AlertConfigResponse(BaseModel):
    alert_rules: list[dict[str, Any]]


class AlertConfigUpdateRequest(BaseModel):
    alert_rules: list[dict[str, Any]]


class OSCALExportRequest(BaseModel):
    export_type: str = "ar"  # ar, ssp, poam
    framework: str | None = None
    system_name: str = "Warlock GRC System"
    description: str = "System assessed by Warlock GRC pipeline"


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    limit: int
    offset: int


class MessageResponse(BaseModel):
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dt_str(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _escape_like(s: str) -> str:
    """Escape SQL LIKE wildcard characters."""
    return _re.sub(r"([%_\\])", r"\\\1", s)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"Invalid date format: {s}")


# Pipeline run tracking
_pipeline_lock = threading.Lock()
_pipeline_running = False
_pipeline_run_id: str | None = None

# In-memory alert config (persisted per-process; swap to DB/file in prod)
_alert_config: dict[str, Any] = {"alert_rules": []}


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Warlock GRC API",
    version="2.0.0a1",
    description="Compliance telemetry pipeline REST API",
)

# Register security middleware (rate limiting, security headers, audit logging)
from warlock.api.middleware import register_middleware  # noqa: E402

register_middleware(app)

PREFIX = "/api/v1"


# =========================================================================
# Health
# =========================================================================


@app.get(PREFIX + "/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        version="2.0.0a1",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# =========================================================================
# Auth
# =========================================================================


@app.post(PREFIX + "/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, body.email, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    from warlock.api.auth import ACCESS_TOKEN_EXPIRE_MINUTES

    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    return TokenResponse(
        access_token=token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        role=user.role,
    )


@app.post(PREFIX + "/auth/register", response_model=UserResponse, status_code=201)
def register(
    body: RegisterRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    # Check if email already exists
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = create_user(db, body.email, body.name, body.password, body.role)
    return _user_to_response(user)


@app.post(PREFIX + "/auth/api-keys", response_model=APIKeyResponse, status_code=201)
def create_api_key_endpoint(
    body: APIKeyCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_keys")),
):
    raw_key, key_hash = generate_api_key()
    expires_at = None
    if body.expires_days:
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_days)

    api_key = APIKey(
        user_id=current_user.id,
        key_hash=key_hash,
        name=body.name,
        scopes=body.scopes,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.flush()

    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        scopes=api_key.scopes or [],
        is_active=True,
        created_at=_dt_str(api_key.created_at) or "",
        last_used=None,
        raw_key=raw_key,
    )


@app.get(PREFIX + "/auth/api-keys", response_model=list[APIKeyResponse])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_keys")),
):
    keys = db.query(APIKey).filter(APIKey.user_id == current_user.id).all()
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            scopes=k.scopes or [],
            is_active=k.is_active,
            created_at=_dt_str(k.created_at) or "",
            last_used=_dt_str(k.last_used),
        )
        for k in keys
    ]


@app.delete(PREFIX + "/auth/api-keys/{key_id}", response_model=MessageResponse)
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_keys")),
):
    api_key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.user_id == current_user.id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.is_active = False
    return MessageResponse(message="API key revoked")


# =========================================================================
# Pipeline
# =========================================================================


def _run_pipeline_background(run_id: str):
    """Execute the pipeline in a background thread."""
    global _pipeline_running, _pipeline_run_id
    try:
        from warlock.db.engine import get_session
        from warlock.connectors.base import registry as connector_registry
        from warlock.normalizers.base import NormalizerRegistry
        from warlock.mappers.control_mapper import ControlMapper
        from warlock.assessors.engine import Assessor
        from warlock.pipeline.bus import EventBus
        from warlock.pipeline.orchestrator import Pipeline

        bus = EventBus()
        normalizers = NormalizerRegistry()
        mapper = ControlMapper()
        assessor = Assessor()
        pipeline = Pipeline(
            connectors=connector_registry,
            normalizers=normalizers,
            mapper=mapper,
            assessor=assessor,
            bus=bus,
        )
        with get_session() as session:
            pipeline.run(session)
    except Exception:
        log.exception("Background pipeline run failed (run_id=%s)", run_id)
    finally:
        with _pipeline_lock:
            _pipeline_running = False


@app.post(PREFIX + "/pipeline/collect", response_model=PipelineCollectResponse)
def pipeline_collect(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("run_pipeline")),
):
    global _pipeline_running, _pipeline_run_id
    with _pipeline_lock:
        if _pipeline_running:
            raise HTTPException(status_code=409, detail="Pipeline is already running")
        _pipeline_running = True
        import uuid

        _pipeline_run_id = str(uuid.uuid4())
        run_id = _pipeline_run_id

    background_tasks.add_task(_run_pipeline_background, run_id)
    return PipelineCollectResponse(message="Pipeline collection started", run_id=run_id)


@app.get(PREFIX + "/pipeline/status", response_model=PipelineStatusResponse)
def pipeline_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    last_run = (
        db.query(ConnectorRun)
        .order_by(ConnectorRun.started_at.desc())
        .first()
    )

    raw_count = db.query(func.count(RawEvent.id)).scalar() or 0
    finding_count = db.query(func.count(Finding.id)).scalar() or 0
    result_count = db.query(func.count(ControlResult.id)).scalar() or 0

    return PipelineStatusResponse(
        running=_pipeline_running,
        last_run_id=last_run.id if last_run else None,
        last_status=last_run.status if last_run else None,
        last_started=_dt_str(last_run.started_at) if last_run else None,
        last_completed=_dt_str(last_run.completed_at) if last_run else None,
        raw_events=raw_count,
        findings=finding_count,
        results=result_count,
    )


# =========================================================================
# Frameworks & Controls
# =========================================================================


@app.get(PREFIX + "/frameworks", response_model=list[FrameworkResponse])
def list_frameworks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    rows = (
        db.query(ControlMapping.framework, func.count(func.distinct(ControlMapping.control_id)))
        .group_by(ControlMapping.framework)
        .all()
    )
    return [FrameworkResponse(name=fw, control_count=cnt) for fw, cnt in rows]


@app.get(PREFIX + "/frameworks/{framework_id}/controls", response_model=list[ControlResponse])
def list_controls(
    framework_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    rows = (
        db.query(
            ControlMapping.framework,
            ControlMapping.control_id,
            ControlMapping.control_family,
            func.count(ControlResult.id),
        )
        .outerjoin(ControlResult, ControlResult.control_mapping_id == ControlMapping.id)
        .filter(ControlMapping.framework == framework_id)
        .group_by(ControlMapping.framework, ControlMapping.control_id, ControlMapping.control_family)
        .all()
    )
    return [
        ControlResponse(framework=fw, control_id=cid, control_family=cf, result_count=cnt)
        for fw, cid, cf, cnt in rows
    ]


# =========================================================================
# Findings
# =========================================================================


@app.get(PREFIX + "/findings", response_model=PaginatedResponse)
def list_findings(
    framework: str | None = Query(None),
    severity: str | None = Query(None),
    observation_type: str | None = Query(None),
    source: str | None = Query(None),
    provider: str | None = Query(None),
    resource_type: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(Finding)

    if framework:
        # Filter findings that have a control mapping to the given framework
        finding_ids_subq = (
            db.query(ControlMapping.finding_id)
            .filter(ControlMapping.framework == framework)
            .subquery()
        )
        query = query.filter(Finding.id.in_(finding_ids_subq))
    if severity:
        query = query.filter(Finding.severity == severity)
    if observation_type:
        query = query.filter(Finding.observation_type == observation_type)
    if source:
        query = query.filter(Finding.source == source)
    if provider:
        query = query.filter(Finding.provider == provider)
    if resource_type:
        query = query.filter(Finding.resource_type == resource_type)
    if date_from:
        query = query.filter(Finding.observed_at >= _parse_dt(date_from))
    if date_to:
        query = query.filter(Finding.observed_at <= _parse_dt(date_to))

    total = query.count()
    rows = query.order_by(Finding.observed_at.desc()).offset(offset).limit(limit).all()

    items = [
        FindingResponse(
            id=f.id,
            title=f.title,
            observation_type=f.observation_type,
            severity=f.severity,
            resource_id=f.resource_id,
            resource_type=f.resource_type,
            source=f.source,
            provider=f.provider,
            observed_at=_dt_str(f.observed_at) or "",
            detail=f.detail,
        )
        for f in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@app.get(PREFIX + "/findings/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse(
        id=f.id,
        title=f.title,
        observation_type=f.observation_type,
        severity=f.severity,
        resource_id=f.resource_id,
        resource_type=f.resource_type,
        source=f.source,
        provider=f.provider,
        observed_at=_dt_str(f.observed_at) or "",
        detail=f.detail,
    )


# =========================================================================
# Control Results
# =========================================================================


@app.get(PREFIX + "/results", response_model=PaginatedResponse)
def list_results(
    framework: str | None = Query(None),
    control_id: str | None = Query(None),
    result_status: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    assessor: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(ControlResult)

    if framework:
        query = query.filter(ControlResult.framework == framework)
    if control_id:
        query = query.filter(ControlResult.control_id == control_id)
    if result_status:
        query = query.filter(ControlResult.status == result_status)
    if severity:
        query = query.filter(ControlResult.severity == severity)
    if assessor:
        query = query.filter(ControlResult.assessor.ilike(f"%{_escape_like(assessor)}%"))
    if date_from:
        query = query.filter(ControlResult.assessed_at >= _parse_dt(date_from))
    if date_to:
        query = query.filter(ControlResult.assessed_at <= _parse_dt(date_to))

    total = query.count()
    rows = query.order_by(ControlResult.assessed_at.desc()).offset(offset).limit(limit).all()

    items = [
        ControlResultResponse(
            id=r.id,
            framework=r.framework,
            control_id=r.control_id,
            status=r.status,
            severity=r.severity,
            assessor=r.assessor,
            assertion_name=r.assertion_name,
            assertion_passed=r.assertion_passed,
            assessed_at=_dt_str(r.assessed_at) or "",
            finding_id=r.finding_id,
            remediation_summary=r.remediation_summary,
        )
        for r in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@app.get(PREFIX + "/results/coverage", response_model=list[CoverageResponse])
def results_coverage(
    framework: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Coverage summary: per-framework counts of each status."""
    query = db.query(
        ControlResult.framework,
        ControlResult.status,
        func.count(ControlResult.id),
    ).group_by(ControlResult.framework, ControlResult.status)

    if framework:
        query = query.filter(ControlResult.framework == framework)

    rows = query.all()

    # Aggregate per framework
    fw_stats: dict[str, dict[str, int]] = {}
    for fw, st, cnt in rows:
        if fw not in fw_stats:
            fw_stats[fw] = {"compliant": 0, "non_compliant": 0, "partial": 0, "not_assessed": 0, "total": 0}
        fw_stats[fw]["total"] += cnt
        if st == "compliant":
            fw_stats[fw]["compliant"] += cnt
        elif st == "non_compliant":
            fw_stats[fw]["non_compliant"] += cnt
        elif st == "partial":
            fw_stats[fw]["partial"] += cnt
        else:
            fw_stats[fw]["not_assessed"] += cnt

    return [
        CoverageResponse(
            framework=fw,
            total=s["total"],
            compliant=s["compliant"],
            non_compliant=s["non_compliant"],
            partial=s["partial"],
            not_assessed=s["not_assessed"],
            rate=round(s["compliant"] / s["total"] * 100, 2) if s["total"] > 0 else 0.0,
        )
        for fw, s in sorted(fw_stats.items())
    ]


@app.get(PREFIX + "/results/posture", response_model=list[PostureResponse])
def results_posture(
    framework: str | None = Query(None),
    control_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Posture scores from the latest snapshot."""
    query = db.query(PostureSnapshot)

    if framework:
        query = query.filter(PostureSnapshot.framework == framework)
    if control_id:
        query = query.filter(PostureSnapshot.control_id == control_id)

    # Get the latest snapshot date
    latest_date_subq = db.query(func.max(PostureSnapshot.snapshot_date)).scalar()
    if latest_date_subq:
        query = query.filter(PostureSnapshot.snapshot_date == latest_date_subq)

    rows = query.order_by(PostureSnapshot.framework, PostureSnapshot.control_id).offset(offset).limit(limit).all()

    return [
        PostureResponse(
            framework=p.framework,
            control_id=p.control_id,
            status=p.status,
            posture_score=p.posture_score,
            sufficiency_score=p.sufficiency_score,
            evidence_sources=p.evidence_sources or [],
            evidence_freshness=p.evidence_freshness_hours,
        )
        for p in rows
    ]


# =========================================================================
# Connectors
# =========================================================================


@app.get(PREFIX + "/connectors", response_model=list[ConnectorResponse])
def list_connectors(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """List connectors with their last run status."""
    # Get the latest connector run per provider
    from sqlalchemy import desc

    subq = (
        db.query(
            ConnectorRun.provider,
            ConnectorRun.source_type,
            func.max(ConnectorRun.started_at).label("max_started"),
        )
        .group_by(ConnectorRun.provider, ConnectorRun.source_type)
        .subquery()
    )

    rows = (
        db.query(ConnectorRun)
        .join(
            subq,
            (ConnectorRun.provider == subq.c.provider)
            & (ConnectorRun.started_at == subq.c.max_started),
        )
        .all()
    )

    # Also include registered connectors that may not have runs yet
    try:
        from warlock.connectors.base import registry

        registered = set(registry.list_types())
    except Exception:
        registered = set()

    seen_providers = set()
    results: list[ConnectorResponse] = []
    for r in rows:
        seen_providers.add(r.provider)
        results.append(
            ConnectorResponse(
                provider=r.provider,
                source_type=r.source_type,
                enabled=True,
                last_run=_dt_str(r.started_at),
                last_status=r.status,
            )
        )

    for provider in sorted(registered - seen_providers):
        results.append(
            ConnectorResponse(
                provider=provider,
                source_type="unknown",
                enabled=True,
                last_run=None,
                last_status=None,
            )
        )

    return results


@app.get(PREFIX + "/connectors/{provider}/status", response_model=ConnectorResponse)
def connector_status(
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    last_run = (
        db.query(ConnectorRun)
        .filter(ConnectorRun.provider == provider)
        .order_by(ConnectorRun.started_at.desc())
        .first()
    )

    if not last_run:
        # Check if the connector is at least registered
        try:
            from warlock.connectors.base import registry

            if provider in registry.list_types():
                return ConnectorResponse(
                    provider=provider,
                    source_type="unknown",
                    enabled=True,
                    last_run=None,
                    last_status=None,
                )
        except Exception:
            pass
        raise HTTPException(status_code=404, detail=f"Connector not found: {provider}")

    return ConnectorResponse(
        provider=last_run.provider,
        source_type=last_run.source_type,
        enabled=True,
        last_run=_dt_str(last_run.started_at),
        last_status=last_run.status,
    )


# =========================================================================
# OSCAL Export
# =========================================================================


@app.post(PREFIX + "/export/oscal")
def export_oscal(
    body: OSCALExportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("export")),
):
    from warlock.export.oscal import OscalExporter

    exporter = OscalExporter()

    if body.export_type == "ar":
        return exporter.export_assessment_results(db, body.framework, body.system_name)
    elif body.export_type == "ssp":
        if not body.framework:
            raise HTTPException(status_code=400, detail="framework is required for SSP export")
        return exporter.export_ssp(db, body.framework, body.system_name, body.description)
    elif body.export_type == "poam":
        return exporter.export_poam(db, body.framework, body.system_name)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown export_type: {body.export_type}. Use ar, ssp, or poam.")


# =========================================================================
# Engagements
# =========================================================================


@app.get(PREFIX + "/engagements", response_model=list[EngagementResponse])
def list_engagements(
    framework: str | None = Query(None),
    engagement_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(AuditEngagement)
    if framework:
        query = query.filter(AuditEngagement.framework == framework)
    if engagement_status:
        query = query.filter(AuditEngagement.status == engagement_status)

    rows = query.order_by(AuditEngagement.created_at.desc()).offset(offset).limit(limit).all()
    return [_engagement_to_response(e) for e in rows]


@app.post(PREFIX + "/engagements", response_model=EngagementResponse, status_code=201)
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


@app.get(PREFIX + "/engagements/{engagement_id}", response_model=EngagementResponse)
def get_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    eng = db.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return _engagement_to_response(eng)


@app.put(PREFIX + "/engagements/{engagement_id}", response_model=EngagementResponse)
def update_engagement(
    engagement_id: str,
    body: EngagementUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    eng = db.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
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


@app.delete(PREFIX + "/engagements/{engagement_id}", response_model=MessageResponse)
def delete_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("delete")),
):
    eng = db.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    eng.status = "archived"
    return MessageResponse(message="Engagement archived")


@app.get(PREFIX + "/engagements/{engagement_id}/evidence", response_model=EvidenceResponse)
def engagement_evidence(
    engagement_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    eng = db.query(AuditEngagement).filter(AuditEngagement.id == engagement_id).first()
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
        findings_query = findings_query.filter(~ControlMapping.control_id.in_(eng.excluded_controls))

    findings_total = findings_query.count()
    findings_rows = findings_query.order_by(Finding.observed_at.desc()).offset(offset).limit(limit).all()

    # Results within the engagement period and framework
    results_query = (
        db.query(ControlResult)
        .filter(
            ControlResult.framework == eng.framework,
            ControlResult.assessed_at >= eng.period_start,
            ControlResult.assessed_at <= eng.period_end,
        )
    )
    if eng.in_scope_controls:
        results_query = results_query.filter(ControlResult.control_id.in_(eng.in_scope_controls))
    if eng.excluded_controls:
        results_query = results_query.filter(~ControlResult.control_id.in_(eng.excluded_controls))

    results_total = results_query.count()
    results_rows = results_query.order_by(ControlResult.assessed_at.desc()).offset(offset).limit(limit).all()

    return EvidenceResponse(
        engagement_id=eng.id,
        framework=eng.framework,
        period_start=_dt_str(eng.period_start) or "",
        period_end=_dt_str(eng.period_end) or "",
        findings_count=findings_total,
        results_count=results_total,
        findings=[
            FindingResponse(
                id=f.id,
                title=f.title,
                observation_type=f.observation_type,
                severity=f.severity,
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                source=f.source,
                provider=f.provider,
                observed_at=_dt_str(f.observed_at) or "",
                detail=f.detail,
            )
            for f in findings_rows
        ],
        results=[
            ControlResultResponse(
                id=r.id,
                framework=r.framework,
                control_id=r.control_id,
                status=r.status,
                severity=r.severity,
                assessor=r.assessor,
                assertion_name=r.assertion_name,
                assertion_passed=r.assertion_passed,
                assessed_at=_dt_str(r.assessed_at) or "",
                finding_id=r.finding_id,
                remediation_summary=r.remediation_summary,
            )
            for r in results_rows
        ],
    )


# =========================================================================
# Audit Package (structured evidence for auditors)
# =========================================================================


@app.get(PREFIX + "/engagements/{engagement_id}/package")
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


# =========================================================================
# Audit Trail
# =========================================================================


@app.get(PREFIX + "/audit-trail", response_model=PaginatedResponse)
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
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(AuditEntry)

    if action:
        query = query.filter(AuditEntry.action == action)
    if entity_type:
        query = query.filter(AuditEntry.entity_type == entity_type)
    if entity_id:
        query = query.filter(AuditEntry.entity_id == entity_id)
    if actor:
        query = query.filter(AuditEntry.actor.ilike(f"%{_escape_like(actor)}%"))
    if date_from:
        query = query.filter(AuditEntry.created_at >= _parse_dt(date_from))
    if date_to:
        query = query.filter(AuditEntry.created_at <= _parse_dt(date_to))

    total = query.count()
    rows = query.order_by(AuditEntry.sequence.desc()).offset(offset).limit(limit).all()

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


@app.get(PREFIX + "/audit-trail/verify", response_model=AuditVerifyResponse)
def verify_audit_trail(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.db.audit import AuditTrail

    trail = AuditTrail(db)
    valid, errors = trail.verify_chain()
    total = db.query(func.count(AuditEntry.id)).scalar() or 0
    return AuditVerifyResponse(valid=valid, total_entries=total, errors=errors)


# =========================================================================
# Alerts Config
# =========================================================================


@app.get(PREFIX + "/alerts/config", response_model=AlertConfigResponse)
def get_alert_config(
    current_user: User = Depends(require_permission("read")),
):
    return AlertConfigResponse(alert_rules=_alert_config.get("alert_rules", []))


@app.put(PREFIX + "/alerts/config", response_model=AlertConfigResponse)
def update_alert_config(
    body: AlertConfigUpdateRequest,
    current_user: User = Depends(require_permission("write")),
):
    _alert_config["alert_rules"] = body.alert_rules
    return AlertConfigResponse(alert_rules=_alert_config["alert_rules"])


# =========================================================================
# Users (admin)
# =========================================================================


@app.get(PREFIX + "/users", response_model=list[UserResponse])
def list_users(
    role: str | None = Query(None),
    is_active: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    query = db.query(User)
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    rows = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    return [_user_to_response(u) for u in rows]


@app.get(PREFIX + "/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@app.put(PREFIX + "/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    body: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    user = db.query(User).filter(User.id == user_id).first()
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


@app.delete(PREFIX + "/users/{user_id}", response_model=MessageResponse)
def deactivate_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    user.is_active = False
    return MessageResponse(message="User deactivated")


# =========================================================================
# Response builders
# =========================================================================


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


# =========================================================================
# Risk Analysis
# =========================================================================


class RiskAnalyzeRequest(BaseModel):
    framework: str
    iterations: int = 10000


class RiskScenarioResponse(BaseModel):
    name: str
    mean_ale: float
    var_95: float
    var_99: float
    control_effectiveness: float


class RiskPortfolioResponse(BaseModel):
    total_mean_ale: float
    total_var_95: float
    total_var_99: float
    scenario_count: int
    iterations: int


class RiskAnalysisResponse(BaseModel):
    framework: str
    scenarios: list[RiskScenarioResponse]
    portfolio: RiskPortfolioResponse


@app.post(PREFIX + "/risk/analyze", response_model=RiskAnalysisResponse)
async def analyze_risk(
    req: RiskAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Run FAIR Monte Carlo risk quantification for a framework."""
    from warlock.assessors.risk_engine import RiskEngine

    engine = RiskEngine(default_iterations=req.iterations)
    result = engine.analyze_framework_risk(db, req.framework, iterations=req.iterations)

    return RiskAnalysisResponse(
        framework=req.framework,
        scenarios=[
            RiskScenarioResponse(**s) for s in result.get("scenarios", [])
        ],
        portfolio=RiskPortfolioResponse(**result.get("portfolio", {})),
    )


# =========================================================================
# Vendor Risk
# =========================================================================


class VendorScoreResponse(BaseModel):
    vendor_name: str
    vendor_id: str
    overall_score: float
    risk_level: str
    issues_count: int
    criticality_score: float
    security_posture_score: float
    assessment_currency_score: float
    sla_compliance_score: float
    recommendations: list[str]


@app.get(PREFIX + "/vendors/risk", response_model=list[VendorScoreResponse])
def vendor_risk_scores(
    provider: str = Query("securityscorecard"),
    threshold: float = Query(60.0, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Score and monitor vendor risk from SecurityScorecard data."""
    from warlock.assessors.vendor_risk import VendorRiskEngine

    engine = VendorRiskEngine()
    scores = engine.monitor_all(db, provider=provider, high_risk_threshold=threshold)

    return [
        VendorScoreResponse(
            vendor_name=s.vendor_name,
            vendor_id=s.vendor_id,
            overall_score=s.overall_score,
            risk_level=s.risk_level,
            issues_count=s.issues_count,
            criticality_score=s.criticality_score,
            security_posture_score=s.security_posture_score,
            assessment_currency_score=s.assessment_currency_score,
            sla_compliance_score=s.sla_compliance_score,
            recommendations=s.recommendations,
        )
        for s in sorted(scores, key=lambda x: x.overall_score)
    ]


# =========================================================================
# Policy Coverage
# =========================================================================


class PolicyCoverageResponse(BaseModel):
    framework: str
    total_controls: int
    controls_with_policy: int
    coverage_pct: float
    gaps: list[str]
    policy_map: dict[str, list[str]]


@app.get(PREFIX + "/policies/coverage", response_model=PolicyCoverageResponse)
def policy_coverage(
    framework: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Score policy documentation coverage for a framework."""
    from warlock.assessors.policy_discovery import score_policy_coverage

    coverage = score_policy_coverage(db, framework)

    return PolicyCoverageResponse(
        framework=coverage.framework,
        total_controls=coverage.total_controls,
        controls_with_policy=coverage.controls_with_policy,
        coverage_pct=coverage.coverage_pct,
        gaps=coverage.gaps,
        policy_map=coverage.policy_map,
    )


class PolicyGapsResponse(BaseModel):
    framework: str
    gaps: list[str]
    gap_count: int


@app.get(PREFIX + "/policies/gaps", response_model=PolicyGapsResponse)
def policy_gaps(
    framework: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Identify controls with no policy documentation."""
    from warlock.assessors.policy_discovery import identify_policy_gaps

    gaps = identify_policy_gaps(db, framework)

    return PolicyGapsResponse(
        framework=framework,
        gaps=gaps,
        gap_count=len(gaps),
    )


# =========================================================================
# Issue Tracking & Remediation
# =========================================================================


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


@app.get(PREFIX + "/issues/summary", response_model=IssueSummaryResponse)
def issues_summary(
    framework: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.issues import IssueManager
    mgr = IssueManager()
    summary = mgr.summary(db, framework=framework)
    return IssueSummaryResponse(**summary)


@app.get(PREFIX + "/issues", response_model=PaginatedResponse)
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


@app.post(PREFIX + "/issues", response_model=IssueResponse, status_code=201)
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


@app.get(PREFIX + "/issues/{issue_id}", response_model=IssueDetailResponse)
def get_issue(
    issue_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    issue = db.query(Issue).filter(Issue.id == issue_id).first()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    comments = (
        db.query(IssueComment)
        .filter(IssueComment.issue_id == issue_id)
        .order_by(IssueComment.created_at.asc())
        .all()
    )
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


@app.patch(PREFIX + "/issues/{issue_id}", response_model=IssueResponse)
def update_issue(
    issue_id: str,
    body: IssueUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    issue = db.query(Issue).filter(Issue.id == issue_id).first()
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


@app.post(PREFIX + "/issues/{issue_id}/transition", response_model=IssueResponse)
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


@app.post(PREFIX + "/issues/{issue_id}/assign", response_model=IssueResponse)
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


@app.post(PREFIX + "/issues/{issue_id}/accept-risk", response_model=IssueResponse)
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
            db, issue_id, body.owner, body.justification,
            body.expiry_days, actor=current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _issue_to_response(issue)


@app.post(PREFIX + "/issues/{issue_id}/evidence", response_model=IssueResponse)
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


@app.post(PREFIX + "/issues/{issue_id}/comments", response_model=IssueCommentResponse, status_code=201)
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


@app.post(PREFIX + "/issues/auto-create", response_model=list[IssueResponse])
def auto_create_issues(
    body: IssueAutoCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.issues import IssueManager
    mgr = IssueManager()
    issues = mgr.auto_create_from_results(db, framework=body.framework)
    return [_issue_to_response(i) for i in issues]


# =========================================================================
# Attestations
# =========================================================================


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


@app.get(PREFIX + "/attestations", response_model=list[AttestationResponse])
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
    if engagement_id:
        query = query.filter(Attestation.engagement_id == engagement_id)
    if framework:
        query = query.filter(Attestation.framework == framework)
    if attest_status:
        query = query.filter(Attestation.status == attest_status)
    rows = query.order_by(Attestation.created_at.desc()).offset(offset).limit(limit).all()
    return [_attestation_to_response(a) for a in rows]


@app.post(PREFIX + "/attestations", response_model=AttestationResponse, status_code=201)
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


@app.get(PREFIX + "/attestations/{attestation_id}", response_model=AttestationResponse)
def get_attestation(
    attestation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    att = db.query(Attestation).filter(Attestation.id == attestation_id).first()
    if not att:
        raise HTTPException(status_code=404, detail="Attestation not found")
    return _attestation_to_response(att)


@app.post(PREFIX + "/attestations/{attestation_id}/submit", response_model=AttestationResponse)
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


@app.post(PREFIX + "/attestations/{attestation_id}/review", response_model=AttestationResponse)
def review_attestation(
    attestation_id: str,
    body: AttestationReviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AttestationManager
    mgr = AttestationManager()
    try:
        att = mgr.review(db, attestation_id, current_user.email, body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


@app.post(PREFIX + "/attestations/{attestation_id}/approve", response_model=AttestationResponse)
def approve_attestation(
    attestation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.attestations import AttestationManager
    mgr = AttestationManager()
    try:
        att = mgr.approve(db, attestation_id, current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _attestation_to_response(att)


@app.post(PREFIX + "/attestations/{attestation_id}/reject", response_model=AttestationResponse)
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


@app.post(PREFIX + "/engagements/{engagement_id}/generate-assertion", response_model=AttestationResponse)
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


# --- Audit Comments ---


@app.get(PREFIX + "/engagements/{engagement_id}/comments", response_model=list[AuditCommentResponse])
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


@app.post(PREFIX + "/engagements/{engagement_id}/comments", response_model=AuditCommentResponse, status_code=201)
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
            db, engagement_id, body.target_type, body.target_id,
            current_user.email, body.author_role or "practitioner",
            body.content, body.parent_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _audit_comment_to_response(comment)


@app.post(PREFIX + "/comments/{comment_id}/resolve", response_model=AuditCommentResponse)
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


@app.get(PREFIX + "/engagements/{engagement_id}/comments/unresolved", response_model=UnresolvedCountResponse)
def unresolved_comments_count(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.attestations import AuditCollaboration
    collab = AuditCollaboration()
    count = collab.unresolved_count(db, engagement_id)
    return UnresolvedCountResponse(engagement_id=engagement_id, unresolved=count)


# =========================================================================
# System Profiles
# =========================================================================


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


@app.get(PREFIX + "/systems", response_model=list[SystemProfileResponse])
def list_systems(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.system_profile import SystemProfileManager
    mgr = SystemProfileManager()
    profiles = mgr.list_active(db)
    return [_system_profile_to_response(sp) for sp in profiles]


@app.post(PREFIX + "/systems", response_model=SystemProfileResponse, status_code=201)
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


@app.get(PREFIX + "/systems/expiring", response_model=list[SystemProfileResponse])
def expiring_systems(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.system_profile import SystemProfileManager
    mgr = SystemProfileManager()
    profiles = mgr.check_authorization_expiry(db)
    return [_system_profile_to_response(sp) for sp in profiles]


@app.get(PREFIX + "/systems/{system_id}", response_model=SystemProfileResponse)
def get_system(
    system_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    sp = db.query(SystemProfile).filter(SystemProfile.id == system_id).first()
    if not sp:
        raise HTTPException(status_code=404, detail="System profile not found")
    return _system_profile_to_response(sp)


@app.patch(PREFIX + "/systems/{system_id}", response_model=SystemProfileResponse)
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


@app.delete(PREFIX + "/systems/{system_id}", response_model=MessageResponse)
def archive_system(
    system_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("delete")),
):
    sp = db.query(SystemProfile).filter(SystemProfile.id == system_id).first()
    if not sp:
        raise HTTPException(status_code=404, detail="System profile not found")
    sp.is_active = False
    sp.updated_at = datetime.now(timezone.utc)
    db.flush()
    return MessageResponse(message="System profile archived")


@app.get(PREFIX + "/systems/{system_id}/findings", response_model=list[FindingResponse])
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
        FindingResponse(
            id=f.id,
            title=f.title,
            observation_type=f.observation_type,
            severity=f.severity,
            resource_id=f.resource_id,
            resource_type=f.resource_type,
            source=f.source,
            provider=f.provider,
            observed_at=_dt_str(f.observed_at) or "",
            detail=f.detail,
        )
        for f in findings
    ]


@app.get(PREFIX + "/systems/{system_id}/posture", response_model=SystemPostureResponse)
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


@app.get(PREFIX + "/systems/{system_id}/ssp-header")
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


# =========================================================================
# Server entry point
# =========================================================================


def run_server():
    """Entry point for `warlock-api` console script."""
    import uvicorn

    host = os.environ.get("WLK_API_HOST", "0.0.0.0")
    port = int(os.environ.get("WLK_API_PORT", "8000"))
    reload_flag = os.environ.get("WLK_API_RELOAD", "false").lower() == "true"

    uvicorn.run(
        "warlock.api.app:app",
        host=host,
        port=port,
        reload=reload_flag,
        log_level="info",
    )
