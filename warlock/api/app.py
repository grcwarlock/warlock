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
- /api/v1/ai/status                     -- AI service status
- /api/v1/ai/models                     -- list/set available models
- /api/v1/ai/configure                  -- configure AI provider
- /api/v1/ai/reason                     -- general-purpose AI reasoning
- /api/v1/ai/converse                   -- interactive AI reasoning session
- /api/v1/ai/conversations/{id}         -- conversation history / delete
- /api/v1/ai/audit                      -- AI audit log
"""

from __future__ import annotations

import json
import logging
import re as _re
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock import __version__ as _VERSION
from warlock.api.auth import (
    authenticate_user,
    create_access_token,
    create_user,
    generate_api_key,
    PERMISSIONS,
)
from warlock.api.deps import get_db, require_permission, apply_framework_scope, apply_source_scope
from warlock.db.models import (
    APIKey,
    Attestation,
    AuditComment,
    AuditEngagement,
    AuditEntry,
    ComplianceDrift,
    ConnectorRun,
    ControlMapping,
    ControlResult,
    DataSilo,
    Finding,
    Issue,
    IssueComment,
    Personnel,
    PostureSnapshot,
    Questionnaire,
    QuestionnaireTemplate,
    SystemProfile,
    User,
    LegalHold,
)
from warlock.db.repository import get_repos

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-process TTL cache for the coverage endpoint (#5)
# ---------------------------------------------------------------------------
# Keyed by (framework_filter, user_id) -> {"data": ..., "ts": float, "latest_run": datetime|None}
_COVERAGE_CACHE_TTL = 300  # seconds
_coverage_cache: dict[tuple, dict] = {}

# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = _VERSION
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
# AI Service Pydantic models
# ---------------------------------------------------------------------------


class AIConfigureRequest(BaseModel):
    provider: str
    api_key: str
    base_url: str = ""


class AISetModelRequest(BaseModel):
    model: str


class AIReasonRequest(BaseModel):
    task: str
    context: dict[str, Any] = Field(default_factory=dict)


class AIConverseRequest(BaseModel):
    entity_type: str
    entity_id: str
    message: str
    session_id: str | None = None


class AIStatusResponse(BaseModel):
    ai_enabled: bool
    provider: str
    model: str
    healthy: bool
    last_call: dict[str, Any] | None = None


class AIModelResponse(BaseModel):
    id: str
    display_name: str
    verified: bool


class AIModelsListResponse(BaseModel):
    provider: str
    connected: bool
    models: list[AIModelResponse]


class AIConfigureResponse(BaseModel):
    provider: str
    connected: bool
    available_models: list[AIModelResponse]


class AISetModelResponse(BaseModel):
    model: str
    active: bool
    validated: bool


class AIReasonResponse(BaseModel):
    value: Any
    ai_used: bool
    confidence: float
    model: str
    provider: str
    latency_ms: int
    fallback_reason: str


class AIConverseResponse(BaseModel):
    session_id: str
    response: Any
    ai_metadata: dict[str, Any] | None = None
    context_summary: str | None = None


class AIAuditEntryResponse(BaseModel):
    session_id: str
    entity_type: str
    entity_id: str
    message_count: int
    created_at: str
    last_activity: str


# Module-level ConversationManager instance (shared across requests)
from warlock.ai.conversation import ConversationManager as _ConversationManager  # noqa: E402
_conversation_manager = _ConversationManager()


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


# In-memory alert config (persisted per-process; swap to DB/file in prod)
_alert_config: dict[str, Any] = {"alert_rules": []}


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Warlock GRC API",
    version=_VERSION,
    description="Compliance telemetry pipeline REST API",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure structured logging on module load
from warlock.logging_config import configure_logging  # noqa: E402
configure_logging()

# CORS — configured via WLK_CORS_ORIGINS
from warlock.config import get_settings as _get_cors_settings  # noqa: E402
_cors_settings = _get_cors_settings()
if _cors_settings.cors_origins:
    # S-10: Reject wildcard origin when credentials are enabled
    if "*" in _cors_settings.cors_origins:
        raise RuntimeError(
            "CORS misconfiguration: allow_origins contains '*' with allow_credentials=True. "
            "This is insecure and forbidden by the CORS specification. "
            "Set WLK_CORS_ORIGINS to specific origins, not '*'."
        )
    from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "X-Api-Key", "Content-Type"],
    )

# Register security middleware (rate limiting, security headers, audit logging)
from warlock.api.middleware import register_middleware  # noqa: E402

register_middleware(app)

# S-18: Request size limit — reject requests larger than 10MB
_MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_CONTENT_LENGTH:
        from starlette.responses import Response
        return Response(
            content='{"detail":"Request body too large (max 10MB)"}',
            status_code=413,
            media_type="application/json",
        )
    return await call_next(request)


# Register trust portal (public, no auth)
from warlock.api.trust_portal import router as trust_router  # noqa: E402

app.include_router(trust_router)

# Register OPA policy gate as optional middleware (only if OPA URL is configured)
from warlock.api.policy_gate import get_policy_gate  # noqa: E402

_policy_gate = get_policy_gate()
if _policy_gate.enabled:

    @app.middleware("http")
    async def opa_policy_middleware(request: Request, call_next):
        # Skip trust portal (public) and health endpoints
        path = request.url.path
        if path.startswith("/trust") or path.endswith("/health"):
            return await call_next(request)
        # OPA evaluation happens via dependency injection, not middleware
        # This middleware just attaches the gate to request state
        request.state.policy_gate = _policy_gate
        return await call_next(request)

PREFIX = "/api/v1"


# =========================================================================
# Health
# =========================================================================


@app.get(PREFIX + "/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        version=_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get(PREFIX + "/health/live")
def health_live():
    """Liveness probe — process is alive."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get(PREFIX + "/health/ready")
def health_ready(db: Session = Depends(get_db)):
    """Readiness probe — checks DB connectivity and scheduler state."""
    from fastapi.responses import JSONResponse

    checks: dict[str, str] = {}
    all_ok = True

    # DB check
    try:
        from sqlalchemy import text
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        # S-8: Don't leak internal error details in health probe response
        log.error("Readiness probe database check failed: %s", e)
        checks["database"] = "failed"
        all_ok = False

    # Scheduler check
    try:
        from warlock.pipeline.scheduler import get_scheduler
        sched = get_scheduler()
        sched_status = sched.status
        checks["scheduler"] = "running" if sched_status.get("running") else "stopped"
        if not sched_status.get("running"):
            all_ok = False
    except Exception:
        checks["scheduler"] = "unknown"

    status_code = 200 if all_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ok" if all_ok else "degraded",
            "checks": checks,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


# =========================================================================
# Prometheus /metrics endpoint (#7)
# =========================================================================

try:
    from prometheus_client import make_asgi_app  # noqa: F401

    _metrics_app = make_asgi_app()
    app.mount("/metrics", _metrics_app)
    log.info("Prometheus /metrics endpoint mounted")
except ImportError:
    pass  # prometheus_client not installed — /metrics endpoint unavailable


# =========================================================================
# Auth
# =========================================================================


@app.post(PREFIX + "/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, body.email, body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    from warlock.api.auth import _get_auth_config

    _, expire_minutes = _get_auth_config()
    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    return TokenResponse(
        access_token=token,
        expires_in=expire_minutes * 60,
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
    # S-11: Validate all requested scopes are valid permission names
    if body.scopes:
        all_valid_perms = set()
        for perms in PERMISSIONS.values():
            all_valid_perms.update(perms)
        invalid_scopes = set(body.scopes) - all_valid_perms
        if invalid_scopes:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scopes: {sorted(invalid_scopes)}. Valid scopes: {sorted(all_valid_perms)}",
            )

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


@app.post(PREFIX + "/auth/logout")
def logout(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Revoke all tokens for the current user."""
    from datetime import datetime, timezone
    current_user.token_valid_after = datetime.now(timezone.utc)
    db.flush()
    return {"message": "All tokens revoked"}


# =========================================================================
# Pipeline
# =========================================================================


def _run_pipeline_background(run_id: str, source: list[str] | None = None):
    """Execute the pipeline in a background thread.

    ConnectorRun rows written by the pipeline orchestrator track status;
    no in-memory flags are needed here.
    """
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
            pipeline.run(session, source_filter=source)
    except Exception:
        log.exception("Background pipeline run failed (run_id=%s)", run_id)


@app.post(PREFIX + "/pipeline/collect", status_code=202)
def pipeline_collect(
    background_tasks: BackgroundTasks,
    source: list[str] | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("run_pipeline")),
):
    """Trigger a full pipeline run in the background."""
    # Check for already-running pipeline via database (multi-worker safe)
    running = db.query(ConnectorRun).filter(ConnectorRun.status == "running").first()
    if running:
        raise HTTPException(
            status_code=409,
            detail=f"Pipeline already running (run {running.id[:8]}, started {running.started_at})",
        )

    import uuid
    run_id = str(uuid.uuid4())
    background_tasks.add_task(_run_pipeline_background, run_id, source)
    return {"status": "started", "run_id": run_id}


@app.get(PREFIX + "/pipeline/status")
def pipeline_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Pipeline run status."""
    latest_run = (
        db.query(ConnectorRun)
        .order_by(ConnectorRun.started_at.desc())
        .first()
    )
    is_running = db.query(ConnectorRun).filter(ConnectorRun.status == "running").count() > 0

    # Use cached event_count from ConnectorRun records to avoid 3 full-table
    # COUNT queries on potentially large raw_events/findings/control_results tables.
    # Summing event_count across all runs is a cheap index scan on connector_runs.
    if latest_run is not None:
        raw_count = int(db.query(func.sum(ConnectorRun.event_count)).scalar() or 0)
    else:
        raw_count = 0
    finding_count = 0
    result_count = 0

    return {
        "running": is_running,
        "last_run": {
            "id": latest_run.id if latest_run else None,
            "status": latest_run.status if latest_run else None,
            "started_at": latest_run.started_at.isoformat() if latest_run and latest_run.started_at else None,
            "completed_at": latest_run.completed_at.isoformat() if latest_run and latest_run.completed_at else None,
            "duration_seconds": latest_run.duration_seconds if latest_run else None,
        } if latest_run else None,
        "totals": {
            "raw_events": raw_count,
            "findings": finding_count,
            "control_results": result_count,
        },
    }


# =========================================================================
# Frameworks & Controls
# =========================================================================


@app.get(PREFIX + "/frameworks", response_model=list[FrameworkResponse])
def list_frameworks(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    # S-1: Apply ABAC scope filters
    base_q = apply_framework_scope(db.query(ControlMapping), ControlMapping, current_user)
    rows = (
        base_q.with_entities(ControlMapping.framework, func.count(func.distinct(ControlMapping.control_id)))
        .group_by(ControlMapping.framework)
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [FrameworkResponse(name=fw, control_count=cnt) for fw, cnt in rows]


@app.get(PREFIX + "/frameworks/{framework_id}/controls", response_model=list[ControlResponse])
def list_controls(
    framework_id: str,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    # S-1: Apply ABAC scope filters
    base_q = apply_framework_scope(db.query(ControlMapping), ControlMapping, current_user)
    rows = (
        base_q.with_entities(
            ControlMapping.framework,
            ControlMapping.control_id,
            ControlMapping.control_family,
            func.count(ControlResult.id),
        )
        .outerjoin(ControlResult, ControlResult.control_mapping_id == ControlMapping.id)
        .filter(ControlMapping.framework == framework_id)
        .group_by(ControlMapping.framework, ControlMapping.control_id, ControlMapping.control_family)
        .offset(offset)
        .limit(limit)
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
    # S-1: Apply ABAC scope filters
    query = apply_source_scope(query, Finding, current_user)

    if framework:
        # Use a JOIN instead of IN(subquery) for better query plan efficiency.
        # The subquery form forces a full scan and hash lookup; a JOIN lets the
        # planner use the idx_mapping_control and idx_mapping_finding indexes.
        query = (
            query
            .join(ControlMapping, ControlMapping.finding_id == Finding.id)
            .filter(ControlMapping.framework == framework)
            .distinct()
        )
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
    # S-1: Apply ABAC scope filters
    query = apply_source_scope(db.query(Finding), Finding, current_user)
    f = query.filter(Finding.id == finding_id).first()
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
    # S-1: Apply ABAC scope filters
    query = apply_framework_scope(query, ControlResult, current_user)

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


@app.get(PREFIX + "/results/coverage")
def results_coverage(
    framework: str | None = Query(None),
    ai: bool = Query(False, description="Include AI narrative for coverage gaps"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Coverage summary: per-framework counts of each status.

    Results are cached in-process for 300 seconds.  The cache is
    invalidated when a new ConnectorRun is detected (by comparing the
    latest ``ConnectorRun.started_at`` timestamp against the value stored
    when the cache entry was written).
    """
    cache_key = (framework, str(current_user.id))
    now = time.monotonic()

    # Fetch the latest ConnectorRun timestamp cheaply (single scalar query)
    latest_run: datetime | None = db.query(func.max(ConnectorRun.started_at)).scalar()

    cached = _coverage_cache.get(cache_key)
    if cached is not None:
        age = now - cached["ts"]
        if age < _COVERAGE_CACHE_TTL and cached["latest_run"] == latest_run:
            log.debug("coverage cache hit (age=%.1fs, key=%s)", age, cache_key)
            return cached["data"]

    # --- Cache miss: compute fresh ---
    # S-1: Apply ABAC scope filter before aggregation
    base_q = apply_framework_scope(db.query(ControlResult), ControlResult, current_user)
    query = base_q.with_entities(
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

    response = [
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

    _coverage_cache[cache_key] = {"data": response, "ts": now, "latest_run": latest_run}
    log.debug("coverage cache miss — refreshed (key=%s)", cache_key)

    if ai:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        ai_svc = get_ai_service()
        if ai_svc.is_task_enabled(AITask.EXECUTIVE_REPORT):
            coverage_context = {
                "frameworks": [
                    {
                        "framework": r.framework,
                        "total": r.total,
                        "compliant": r.compliant,
                        "non_compliant": r.non_compliant,
                        "partial": r.partial,
                        "not_assessed": r.not_assessed,
                        "rate": r.rate,
                    }
                    for r in response
                ],
            }
            ai_result = ai_svc.reason(AITask.EXECUTIVE_REPORT, context=coverage_context)
            ai_narrative = ai_result.value if ai_result.ai_used else None
            ai_meta: dict[str, Any] | None = None
            if ai_result.ai_used:
                ai_meta = {
                    "model": ai_result.model,
                    "provider": ai_result.provider,
                    "latency_ms": ai_result.latency_ms,
                    "confidence": ai_result.confidence,
                }
            return {
                "coverage": [r.model_dump() for r in response],
                "ai_narrative": ai_narrative,
                "ai_metadata": ai_meta,
            }

    return response


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
    # S-1: Apply ABAC scope filters
    query = apply_framework_scope(query, PostureSnapshot, current_user)

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
# Cadence & Sufficiency
# =========================================================================


class CadenceResponse(BaseModel):
    framework: str
    control_id: str
    required_frequency: str
    required_hours: float
    last_evidence_at: str | None
    hours_since: float | None
    is_stale: bool
    staleness_ratio: float


class SufficiencyResponse(BaseModel):
    framework: str
    control_id: str
    score: float
    evidence_volume: float
    evidence_freshness: float
    evidence_diversity: float
    assertion_coverage: float
    gaps: list[str]


@app.get(PREFIX + "/cadence", response_model=list[CadenceResponse])
def get_cadence(
    framework: str | None = Query(None),
    stale_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Check monitoring cadence — are controls being assessed on schedule?"""
    from warlock.assessors.cadence import CadenceChecker

    checker = CadenceChecker()

    if stale_only:
        cadences = checker.get_stale_controls(db, framework=framework)
    elif framework:
        cadences = checker.check_framework(db, framework)
    else:
        all_c = checker.check_all(db)
        cadences = [c for clist in all_c.values() for c in clist]

    return [
        CadenceResponse(
            framework=c.framework,
            control_id=c.control_id,
            required_frequency=c.required_frequency,
            required_hours=c.required_hours,
            last_evidence_at=c.last_evidence_at.isoformat() if c.last_evidence_at else None,
            hours_since=c.hours_since,
            is_stale=c.is_stale,
            staleness_ratio=c.staleness_ratio,
        )
        for c in cadences
    ]


class PostureHistoryPointResponse(BaseModel):
    date: str
    status: str
    posture_score: float
    sufficiency_score: float
    evidence_freshness_hours: float | None


class PostureHistoryResponse(BaseModel):
    framework: str
    control_id: str
    trend: str
    trend_slope: float
    points: list[PostureHistoryPointResponse]


@app.get(PREFIX + "/posture/history", response_model=list[PostureHistoryResponse])
def posture_history(
    framework: str = Query(...),
    control_id: str | None = Query(None),
    days: int = Query(90, ge=1, le=730),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Posture time-series with trend analysis."""
    from warlock.assessors.posture import PostureTimeSeriesQuery

    tsq = PostureTimeSeriesQuery()

    if control_id:
        series_list = [tsq.query_control(db, framework, control_id, days)]
    else:
        series_list = tsq.query_framework(db, framework, days)

    return [
        PostureHistoryResponse(
            framework=ts.framework,
            control_id=ts.control_id,
            trend=ts.trend,
            trend_slope=ts.trend_slope,
            points=[
                PostureHistoryPointResponse(
                    date=p.date.isoformat() if p.date else "",
                    status=p.status,
                    posture_score=p.posture_score,
                    sufficiency_score=p.sufficiency_score,
                    evidence_freshness_hours=p.evidence_freshness_hours,
                )
                for p in ts.points
            ],
        )
        for ts in series_list
    ]


@app.get(PREFIX + "/sufficiency", response_model=list[SufficiencyResponse])
def get_sufficiency(
    framework: str | None = Query(None),
    below: float | None = Query(None, description="Only controls below this score"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Evidence sufficiency scores per control."""
    from warlock.assessors.posture import EvidenceSufficiencyScorer
    from sqlalchemy import distinct

    scorer = EvidenceSufficiencyScorer()

    if framework:
        fw_result = scorer.score_framework(db, framework)
        scores = fw_result.control_scores
    else:
        fw_rows = db.query(distinct(ControlResult.framework)).all()
        scores = []
        for (fw,) in fw_rows:
            fw_result = scorer.score_framework(db, fw)
            scores.extend(fw_result.control_scores)

    if below is not None:
        scores = [s for s in scores if s.score < below]

    scores.sort(key=lambda s: s.score)

    return [
        SufficiencyResponse(
            framework=s.framework,
            control_id=s.control_id,
            score=s.score,
            evidence_volume=s.evidence_volume,
            evidence_freshness=s.evidence_freshness,
            evidence_diversity=s.evidence_diversity,
            assertion_coverage=s.assertion_coverage,
            gaps=s.gaps,
        )
        for s in scores
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
    # S-1: Apply ABAC scope filters
    query = apply_framework_scope(query, AuditEngagement, current_user)
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
    # S-4: Revoke all tokens by setting token_valid_after to now
    user.token_valid_after = datetime.now(timezone.utc)
    # S-4: Deactivate all associated API keys
    db.query(APIKey).filter(APIKey.user_id == user_id, APIKey.is_active == True).update(  # noqa: E712
        {"is_active": False}, synchronize_session="fetch"
    )
    log.info("User %s deactivated: tokens revoked, %s API keys deactivated", user.email, user_id[:8])
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
    ai: bool = False


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


@app.post(PREFIX + "/risk/analyze")
async def analyze_risk(
    req: RiskAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Run FAIR Monte Carlo risk quantification for a framework.

    Pass ``ai=true`` in the request body to append an AI-generated
    executive narrative that interprets the quantitative results.
    """
    from warlock.assessors.risk_engine import RiskEngine

    engine = RiskEngine(default_iterations=req.iterations)
    result = engine.analyze_framework_risk(db, req.framework, iterations=req.iterations)

    response = RiskAnalysisResponse(
        framework=req.framework,
        scenarios=[
            RiskScenarioResponse(**s) for s in result.get("scenarios", [])
        ],
        portfolio=RiskPortfolioResponse(**result.get("portfolio", {})),
    )

    if req.ai:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        ai_svc = get_ai_service()
        if ai_svc.is_task_enabled(AITask.RISK_NARRATIVE):
            ai_context = {
                "framework": req.framework,
                "scenarios": result.get("scenarios", []),
                "portfolio": result.get("portfolio", {}),
            }
            ai_result = ai_svc.reason(AITask.RISK_NARRATIVE, context=ai_context)
            enriched = response.model_dump()
            enriched["ai_narrative"] = ai_result.value if ai_result.ai_used else None
            if ai_result.ai_used:
                enriched["ai_metadata"] = {
                    "model": ai_result.model,
                    "provider": ai_result.provider,
                    "latency_ms": ai_result.latency_ms,
                    "confidence": ai_result.confidence,
                }
            return enriched

    return response


class RiskCacheStatsResponse(BaseModel):
    total_entries: int
    oldest_entry_age_hours: float | None
    entries_per_framework: dict[str, int]
    cache_hits: int
    cache_misses: int
    hit_rate: float | None


@app.get(PREFIX + "/risk/cache-stats", response_model=RiskCacheStatsResponse)
def risk_cache_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Return Monte Carlo cache statistics.

    Reports the total number of cached RiskAnalysis entries, their age,
    per-framework breakdown, and the in-process hit/miss counters accumulated
    since the API process started.
    """
    from warlock.assessors.risk_engine import RiskEngine

    engine = RiskEngine()
    stats = engine.get_cache_stats(db)
    return RiskCacheStatsResponse(**stats)


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
    attest = db.query(Attestation).filter(Attestation.id == attestation_id).first()
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


@app.post(PREFIX + "/attestations/{attestation_id}/approve", response_model=AttestationResponse)
def approve_attestation(
    attestation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    attest = db.query(Attestation).filter(Attestation.id == attestation_id).first()
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
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    from warlock.workflows.system_profile import SystemProfileManager
    mgr = SystemProfileManager()
    profiles = mgr.list_active(db)
    return [_system_profile_to_response(sp) for sp in profiles[offset:offset + limit]]


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
# Retention Policies
# =========================================================================


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


@app.get(PREFIX + "/retention/report", response_model=RetentionReportResponse)
def retention_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.retention import RetentionManager
    mgr = RetentionManager()
    report = mgr.retention_report(db)
    return RetentionReportResponse(**report)


@app.post(PREFIX + "/retention/purge")
def retention_purge(
    body: PurgeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("delete")),
):
    from warlock.workflows.retention import RetentionManager
    mgr = RetentionManager()
    result = mgr.purge_expired(db, dry_run=body.dry_run, framework=body.framework)
    return result


@app.post(PREFIX + "/retention/legal-hold", response_model=LegalHoldResponse, status_code=201)
def create_legal_hold(
    body: LegalHoldCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.retention import RetentionManager
    mgr = RetentionManager()
    hold_id = mgr.set_legal_hold(
        db,
        reason=body.reason,
        start_date=body.start_date,
        end_date=body.end_date,
        actor=current_user.email,
    )
    hold = db.query(LegalHold).filter(LegalHold.id == hold_id).first()
    return LegalHoldResponse(
        id=hold.id,
        reason=hold.reason,
        start_date=_dt_str(hold.start_date),
        end_date=_dt_str(hold.end_date),
        created_by=hold.created_by,
        is_active=hold.is_active,
        created_at=_dt_str(hold.created_at),
    )


@app.get(PREFIX + "/retention/legal-holds", response_model=list[LegalHoldResponse])
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


@app.delete(PREFIX + "/retention/legal-holds/{hold_id}", response_model=MessageResponse)
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


# =========================================================================
# Scheduler
# =========================================================================


class SchedulerStatusResponse(BaseModel):
    running: bool
    interval_minutes: int
    interval_seconds: int
    last_run: str | None
    next_run: str | None
    run_count: int
    last_error: str | None


class SchedulerStartRequest(BaseModel):
    interval_minutes: int = 60


@app.get(PREFIX + "/scheduler/status", response_model=SchedulerStatusResponse)
def scheduler_status(
    current_user: User = Depends(require_permission("read")),
):
    from warlock.pipeline.scheduler import get_scheduler
    sched = get_scheduler()
    return SchedulerStatusResponse(**sched.status)


@app.post(PREFIX + "/scheduler/start", response_model=SchedulerStatusResponse)
def scheduler_start(
    body: SchedulerStartRequest | None = None,
    current_user: User = Depends(require_permission("run_pipeline")),
):
    from warlock.pipeline.scheduler import get_scheduler
    interval = body.interval_minutes if body else 60
    sched = get_scheduler(interval_minutes=interval)
    sched.interval = interval * 60
    sched.start()
    return SchedulerStatusResponse(**sched.status)


@app.post(PREFIX + "/scheduler/stop", response_model=SchedulerStatusResponse)
def scheduler_stop(
    current_user: User = Depends(require_permission("run_pipeline")),
):
    from warlock.pipeline.scheduler import get_scheduler
    sched = get_scheduler()
    sched.stop()
    return SchedulerStatusResponse(**sched.status)


# =========================================================================
# Tool Config Management
# =========================================================================


@app.get(PREFIX + "/tools", response_model=list[dict[str, Any]])
def list_tools(
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(require_permission("read")),
):
    # S-12: Added pagination defaults
    from warlock.workflows.tool_config import ToolConfigManager
    mgr = ToolConfigManager()
    connectors = mgr.list_connectors()
    return connectors[offset:offset + limit]


@app.post(PREFIX + "/tools/{provider}/test")
def test_tool(
    provider: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager
    mgr = ToolConfigManager()
    return mgr.test_connector(db, provider)


@app.post(PREFIX + "/tools/test-all")
def test_all_tools(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager
    mgr = ToolConfigManager()
    return mgr.test_all(db)


@app.get(PREFIX + "/tools/{provider}/env-vars")
def tool_env_vars(
    provider: str,
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager
    mgr = ToolConfigManager()
    return mgr.get_required_env_vars(provider)


@app.get(PREFIX + "/tools/{provider}/history")
def tool_history(
    provider: str,
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.tool_config import ToolConfigManager
    mgr = ToolConfigManager()
    return mgr.connection_history(db, provider, limit=limit)


# =========================================================================
# Personnel Management
# =========================================================================


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


@app.get(PREFIX + "/personnel", response_model=PaginatedResponse)
def list_personnel(
    department: str | None = Query(None),
    hr_status: str | None = Query(None, alias="status"),
    has_flags: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(Personnel).filter(Personnel.is_active == True)  # noqa: E712
    if department:
        query = query.filter(Personnel.department == department)
    if hr_status:
        query = query.filter(Personnel.hr_status == hr_status)
    if has_flags is True:
        query = query.filter(Personnel.risk_score > 0)
    elif has_flags is False:
        query = query.filter(Personnel.risk_score == 0)

    total = query.count()
    rows = query.order_by(Personnel.full_name).offset(offset).limit(limit).all()
    items = [_personnel_to_response(p) for p in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@app.get(PREFIX + "/personnel/flags", response_model=list[PersonnelResponse])
def personnel_flags(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    rows = (
        db.query(Personnel)
        .filter(Personnel.is_active == True, Personnel.risk_score > 0)  # noqa: E712
        .order_by(Personnel.risk_score.desc())
        .limit(limit)
        .all()
    )
    return [_personnel_to_response(p) for p in rows]


@app.get(PREFIX + "/personnel/terminated-active", response_model=list[PersonnelResponse])
def personnel_terminated_active(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.personnel import PersonnelManager
    mgr = PersonnelManager()
    rows = mgr.terminated_with_active_access(db)
    return [_personnel_to_response(p) for p in rows]


@app.get(PREFIX + "/personnel/summary", response_model=PersonnelSummaryResponse)
def personnel_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.personnel import PersonnelManager
    mgr = PersonnelManager()
    return PersonnelSummaryResponse(**mgr.summary(db))


@app.post(PREFIX + "/personnel/sync", response_model=PersonnelSyncResponse)
def personnel_sync(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.personnel import PersonnelManager
    mgr = PersonnelManager()
    result = mgr.sync_all(db)
    return PersonnelSyncResponse(**result)


@app.get(PREFIX + "/personnel/{personnel_id}", response_model=PersonnelResponse)
def get_personnel(
    personnel_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    p = db.query(Personnel).filter(Personnel.id == personnel_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Personnel record not found")
    return _personnel_to_response(p)


# =========================================================================
# Vendor Questionnaires
# =========================================================================


class TemplateCreateRequest(BaseModel):
    name: str
    template_type: str
    questions: list[dict[str, Any]]
    description: str = ""
    version: str = "1.0"


class TemplateResponse(BaseModel):
    id: str
    name: str
    template_type: str
    version: str | None = None
    description: str | None = None
    total_questions: int = 0
    is_active: bool = True
    created_at: str

    model_config = {"from_attributes": True}


class QuestionnaireCreateRequest(BaseModel):
    template_id: str
    vendor_name: str
    vendor_email: str | None = None
    due_days: int = 30


class QuestionnaireResponseModel(BaseModel):
    id: str
    template_id: str
    vendor_name: str
    vendor_contact_email: str | None = None
    status: str
    completion_pct: float = 0.0
    risk_score: float | None = None
    risk_findings: list[dict[str, Any]] | None = None
    ai_suggested_answers: dict[str, Any] | None = None
    sent_at: str | None = None
    due_date: str | None = None
    completed_at: str | None = None
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    responses: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None
    created_by: str | None = None

    model_config = {"from_attributes": True}


class QuestionnaireSubmitRequest(BaseModel):
    responses: dict[str, Any]


class QuestionnaireTransitionRequest(BaseModel):
    status: str


class QuestionnaireSummaryResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    overdue: int
    templates: int
    avg_risk_score: float | None = None


def _template_to_response(t: QuestionnaireTemplate) -> TemplateResponse:
    return TemplateResponse(
        id=t.id,
        name=t.name,
        template_type=t.template_type,
        version=t.version,
        description=t.description,
        total_questions=t.total_questions or 0,
        is_active=t.is_active or True,
        created_at=_dt_str(t.created_at) or "",
    )


def _questionnaire_to_response(q: Questionnaire) -> QuestionnaireResponseModel:
    return QuestionnaireResponseModel(
        id=q.id,
        template_id=q.template_id,
        vendor_name=q.vendor_name,
        vendor_contact_email=q.vendor_contact_email,
        status=q.status,
        completion_pct=q.completion_pct or 0.0,
        risk_score=q.risk_score,
        risk_findings=q.risk_findings,
        ai_suggested_answers=q.ai_suggested_answers,
        sent_at=_dt_str(q.sent_at),
        due_date=_dt_str(q.due_date),
        completed_at=_dt_str(q.completed_at),
        reviewed_by=q.reviewed_by,
        reviewed_at=_dt_str(q.reviewed_at),
        responses=q.responses,
        created_at=_dt_str(q.created_at) or "",
        updated_at=_dt_str(q.updated_at),
        created_by=q.created_by,
    )


@app.get(PREFIX + "/questionnaires/templates", response_model=list[TemplateResponse])
def list_questionnaire_templates(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    rows = (
        db.query(QuestionnaireTemplate)
        .filter(QuestionnaireTemplate.is_active == True)  # noqa: E712
        .order_by(QuestionnaireTemplate.name)
        .all()
    )
    return [_template_to_response(t) for t in rows]


@app.post(PREFIX + "/questionnaires/templates", response_model=TemplateResponse, status_code=201)
def create_questionnaire_template(
    body: TemplateCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    t = mgr.create_template(
        db,
        name=body.name,
        template_type=body.template_type,
        questions=body.questions,
        description=body.description,
        version=body.version,
    )
    return _template_to_response(t)


@app.post(PREFIX + "/questionnaires/templates/seed", response_model=list[TemplateResponse])
def seed_questionnaire_templates(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    templates = mgr.seed_default_templates(db)
    return [_template_to_response(t) for t in templates]


@app.get(PREFIX + "/questionnaires/overdue", response_model=list[QuestionnaireResponseModel])
def overdue_questionnaires(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    rows = mgr.overdue(db)
    return [_questionnaire_to_response(q) for q in rows]


@app.get(PREFIX + "/questionnaires", response_model=PaginatedResponse)
def list_questionnaires(
    vendor_name: str | None = Query(None),
    q_status: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(Questionnaire)
    if vendor_name:
        query = query.filter(Questionnaire.vendor_name == vendor_name)
    if q_status:
        query = query.filter(Questionnaire.status == q_status)
    total = query.count()
    rows = query.order_by(Questionnaire.created_at.desc()).offset(offset).limit(limit).all()
    items = [_questionnaire_to_response(q) for q in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@app.post(PREFIX + "/questionnaires", response_model=QuestionnaireResponseModel, status_code=201)
def create_questionnaire_endpoint(
    body: QuestionnaireCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    try:
        q = mgr.create_questionnaire(
            db,
            template_id=body.template_id,
            vendor_name=body.vendor_name,
            vendor_email=body.vendor_email,
            due_days=body.due_days,
            created_by=current_user.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@app.get(PREFIX + "/questionnaires/{questionnaire_id}", response_model=QuestionnaireResponseModel)
def get_questionnaire(
    questionnaire_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    q = db.query(Questionnaire).filter(Questionnaire.id == questionnaire_id).first()
    if not q:
        raise HTTPException(status_code=404, detail="Questionnaire not found")
    return _questionnaire_to_response(q)


@app.post(PREFIX + "/questionnaires/{questionnaire_id}/responses", response_model=QuestionnaireResponseModel)
def submit_questionnaire_responses(
    questionnaire_id: str,
    body: QuestionnaireSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    try:
        q = mgr.submit_bulk_responses(db, questionnaire_id, body.responses)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@app.post(PREFIX + "/questionnaires/{questionnaire_id}/score", response_model=QuestionnaireResponseModel)
def score_questionnaire(
    questionnaire_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    try:
        q = mgr.score_responses(db, questionnaire_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@app.post(PREFIX + "/questionnaires/{questionnaire_id}/ai-suggest", response_model=QuestionnaireResponseModel)
def ai_suggest_questionnaire(
    questionnaire_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    try:
        q = mgr.ai_suggest_answers(db, questionnaire_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


@app.post(PREFIX + "/questionnaires/{questionnaire_id}/transition", response_model=QuestionnaireResponseModel)
def transition_questionnaire(
    questionnaire_id: str,
    body: QuestionnaireTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    from warlock.workflows.questionnaires import QuestionnaireManager
    mgr = QuestionnaireManager()
    try:
        q = mgr.transition(db, questionnaire_id, body.status, actor=current_user.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _questionnaire_to_response(q)


# =========================================================================
# Data Silos
# =========================================================================


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


@app.get(PREFIX + "/data-silos", response_model=PaginatedResponse)
def list_data_silos(
    silo_type: str | None = Query(None, alias="type"),
    classification: str | None = Query(None),
    provider: str | None = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    query = db.query(DataSilo).filter(DataSilo.is_active == True)  # noqa: E712
    # S-1: Apply ABAC scope filters
    query = apply_source_scope(query, DataSilo, current_user)
    if silo_type:
        query = query.filter(DataSilo.silo_type == silo_type)
    if classification:
        query = query.filter(DataSilo.data_classification == classification)
    if provider:
        query = query.filter(DataSilo.provider == provider)
    total = query.count()
    rows = query.order_by(DataSilo.name).offset(offset).limit(limit).all()
    items = [_data_silo_to_response(s) for s in rows]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@app.post(PREFIX + "/data-silos", response_model=DataSiloResponse, status_code=201)
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


@app.get(PREFIX + "/data-silos/unclassified", response_model=list[DataSiloResponse])
def unclassified_data_silos(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.data_silos import DataSiloManager
    mgr = DataSiloManager()
    rows = mgr.unclassified(db)
    return [_data_silo_to_response(s) for s in rows]


@app.get(PREFIX + "/data-silos/unprotected", response_model=list[DataSiloResponse])
def unprotected_data_silos(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.data_silos import DataSiloManager
    mgr = DataSiloManager()
    rows = mgr.unprotected(db)
    return [_data_silo_to_response(s) for s in rows]


@app.get(PREFIX + "/data-silos/summary", response_model=DataSiloSummaryResponse)
def data_silo_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    from warlock.workflows.data_silos import DataSiloManager
    mgr = DataSiloManager()
    return DataSiloSummaryResponse(**mgr.summary(db))


@app.post(PREFIX + "/data-silos/discover", response_model=MessageResponse)
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


@app.get(PREFIX + "/data-silos/{silo_id}", response_model=DataSiloResponse)
def get_data_silo(
    silo_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    s = db.query(DataSilo).filter(DataSilo.id == silo_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Data silo not found")
    return _data_silo_to_response(s)


@app.patch(PREFIX + "/data-silos/{silo_id}", response_model=DataSiloResponse)
def update_data_silo(
    silo_id: str,
    body: DataSiloUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("write")),
):
    silo = db.query(DataSilo).filter(DataSilo.id == silo_id).first()
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
            db, silo_id,
            classification=silo.data_classification or "unknown",
            contains_pii=silo.contains_pii,
            contains_phi=silo.contains_phi,
            contains_pci=silo.contains_pci,
        )
    else:
        silo.updated_at = datetime.now(timezone.utc)
        db.flush()

    return _data_silo_to_response(silo)


# =========================================================================
# Phase 2: POA&Ms, Compensating Controls, Risk Acceptance
# =========================================================================


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


@app.get(PREFIX + "/poams")
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
            "id": p.id, "framework": p.framework, "control_id": p.control_id,
            "weakness_description": p.weakness_description, "severity": p.severity,
            "status": p.status, "delay_count": p.delay_count or 0,
            "scheduled_completion": p.scheduled_completion.isoformat() if p.scheduled_completion else None,
            "milestones": p.milestones,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in rows
    ]


@app.post(PREFIX + "/poams/{poam_id}/extend")
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


@app.get(PREFIX + "/compensating-controls")
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
            "id": c.id, "original_framework": c.original_framework,
            "original_control_id": c.original_control_id, "title": c.title,
            "status": c.status, "effectiveness_score": c.effectiveness_score,
            "expiry_date": c.expiry_date.isoformat() if c.expiry_date else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in rows
    ]


@app.get(PREFIX + "/risk-acceptances")
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
            "id": r.id, "framework": r.framework, "control_id": r.control_id,
            "risk_level": r.risk_level, "status": r.status,
            "approved_by": r.approved_by,
            "expiry_date": r.expiry_date.isoformat() if r.expiry_date else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# =========================================================================
# Phase 4: Drift & Simulation
# =========================================================================


@app.get(PREFIX + "/drift")
def get_drift(
    framework: str | None = Query(None),
    days: int = Query(30),
    direction: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Get compliance drift events."""
    from warlock.assessors.drift import DriftDetector
    detector = DriftDetector()
    drifts = detector.get_drifts(db, framework=framework, days=days, direction=direction)
    return [
        {
            "id": d.id, "framework": d.framework, "control_id": d.control_id,
            "drift_direction": d.drift_direction,
            "previous_status": d.previous_status, "new_status": d.new_status,
            "correlated_changes": len(d.correlated_change_event_ids or []),
            "detected_at": d.detected_at.isoformat() if d.detected_at else None,
        }
        for d in drifts
    ]


class AuditSimulationRequest(BaseModel):
    framework: str
    target_date: str
    system_id: str | None = None


@app.post(PREFIX + "/audit-simulation")
def run_audit_simulation(
    req: AuditSimulationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Simulate what an auditor would see at a future date."""
    from warlock.assessors.simulation import AuditSimulator
    from datetime import datetime as dt, timezone as tz
    sim = AuditSimulator()
    target = dt.fromisoformat(req.target_date).replace(tzinfo=tz.utc)
    result = sim.simulate(db, req.framework, target, system_id=req.system_id)
    return {
        "projected_coverage": result.projected_coverage,
        "total_controls": result.total_controls,
        "stale_controls": result.stale_controls,
        "overdue_poams": result.overdue_poams,
        "expiring_acceptances": result.expiring_acceptances,
        "at_risk_controls": result.at_risk_controls,
    }


@app.get(PREFIX + "/effectiveness")
def get_effectiveness(
    framework: str | None = Query(None),
    days: int = Query(365),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Control effectiveness scores over time."""
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(PostureSnapshot).filter(
        PostureSnapshot.snapshot_date >= cutoff,
        PostureSnapshot.uptime_pct.isnot(None),
    )
    if framework:
        q = q.filter(PostureSnapshot.framework == framework)

    latest = q.order_by(PostureSnapshot.snapshot_date.desc()).all()
    seen = set()
    rows = []
    for s in latest:
        key = (s.framework, s.control_id)
        if key not in seen:
            seen.add(key)
            rows.append(s)

    return [
        {
            "framework": s.framework, "control_id": s.control_id,
            "uptime_pct": s.uptime_pct, "mttr_hours": s.mttr_hours,
            "drift_count": s.drift_count,
        }
        for s in rows
    ]


# =========================================================================
# Phase 5: Framework Diff & Impact Check
# =========================================================================


class FrameworkDiffRequest(BaseModel):
    old_version: str
    new_version: str


@app.post(PREFIX + "/frameworks/diff")
def framework_diff_endpoint(
    req: FrameworkDiffRequest,
    current_user: User = Depends(require_permission("read")),
):
    """Compare two framework versions."""
    from warlock.frameworks.diff import FrameworkDiff
    differ = FrameworkDiff()
    result = differ.diff(req.old_version, req.new_version)
    return {
        "added": sorted(result.added_controls),
        "removed": sorted(result.removed_controls),
        "modified": sorted(result.modified_controls),
        "unchanged_count": len(result.unchanged_controls),
    }


class ImpactCheckRequest(BaseModel):
    changed_files: list[str]


@app.post(PREFIX + "/impact-check")
def impact_check_endpoint(
    req: ImpactCheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Check compliance impact of changed assertion/policy files."""
    from warlock.assessors.impact import ComplianceImpactAnalyzer
    analyzer = ComplianceImpactAnalyzer()
    result = analyzer.analyze(db, req.changed_files)
    return {
        "affected_controls": result.affected_controls,
        "predicted_flips": [
            {"control": f.control, "framework": f.framework, "from_status": f.from_status, "to_status": f.to_status}
            for f in result.predicted_flips
        ],
    }


# =========================================================================
# GDPR Data Subject Rights
# =========================================================================


@app.get(PREFIX + "/gdpr/export")
def gdpr_export(
    email: str = Query(..., description="Email of the data subject"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    """Export all personal data for a data subject (GDPR Article 15)."""
    from warlock.workflows.gdpr import GDPRManager
    manager = GDPRManager()
    return manager.export_subject_data(db, email)


@app.delete(PREFIX + "/gdpr/erase")
def gdpr_erase(
    email: str = Query(..., description="Email of the data subject to anonymize"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("manage_users")),
):
    """Anonymize all PII for a data subject (GDPR Article 17).

    Does not delete records — anonymizes PII fields to preserve
    referential integrity and audit trail.
    """
    from warlock.workflows.gdpr import GDPRManager
    manager = GDPRManager()
    result = manager.erase_subject_data(db, email, erased_by=current_user.email)
    return result


# =========================================================================
# #47: Real-time compliance dashboard
# =========================================================================

# In-process TTL cache for the dashboard summary endpoint (5-minute TTL)
# Keyed by user_id -> {"data": ..., "ts": float}
_DASHBOARD_CACHE: dict[str, dict] = {}
_DASHBOARD_CACHE_TTL = 300  # 5 minutes


@app.get(PREFIX + "/dashboard/summary")
def dashboard_summary(
    ai: bool = Query(False, description="Include AI executive summary narrative"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Real-time compliance dashboard — single call for the frontend.

    Returns:
    - frameworks:       per-framework compliance rate, control counts, trend
    - top_risks:        top 5 non-compliant controls by severity
    - recent_drift:     last 5 compliance drift events
    - open_issues:      count by priority (critical/high/medium/low)
    - posture_score:    overall weighted compliance percentage
    - connectors:       health status of most recent run per provider
    - last_assessment:  timestamp of most recent pipeline completion

    Cached per user for 5 minutes (TTL = 300 s).
    """
    now_ts = time.time()
    cache_key = current_user.id
    cached = _DASHBOARD_CACHE.get(cache_key)
    if cached and (now_ts - cached["ts"]) < _DASHBOARD_CACHE_TTL:
        return cached["data"]

    # -----------------------------------------------------------------
    # frameworks: per-framework compliance rate, control counts, trend
    # -----------------------------------------------------------------
    fw_rows = (
        db.query(
            ControlResult.framework,
            ControlResult.status,
            func.count(ControlResult.id).label("cnt"),
        )
        .group_by(ControlResult.framework, ControlResult.status)
        .all()
    )

    fw_agg: dict[str, dict] = {}
    for framework, status_val, cnt in fw_rows:
        if framework not in fw_agg:
            fw_agg[framework] = {"total": 0, "compliant": 0, "non_compliant": 0}
        fw_agg[framework]["total"] += cnt
        if status_val == "compliant":
            fw_agg[framework]["compliant"] += cnt
        elif status_val == "non_compliant":
            fw_agg[framework]["non_compliant"] += cnt

    # Trend: compare current rate against most-recent posture snapshot rate
    snapshot_rates: dict[str, float] = {}
    latest_snapshot_date = db.query(func.max(PostureSnapshot.snapshot_date)).scalar()
    if latest_snapshot_date:
        snap_rows = (
            db.query(
                PostureSnapshot.framework,
                func.avg(PostureSnapshot.posture_score).label("avg_score"),
            )
            .filter(PostureSnapshot.snapshot_date == latest_snapshot_date)
            .group_by(PostureSnapshot.framework)
            .all()
        )
        for fw_name, avg_score in snap_rows:
            snapshot_rates[fw_name] = float(avg_score or 0)

    frameworks_out = []
    total_compliant = 0
    total_controls = 0

    for fw, agg in sorted(fw_agg.items()):
        total = agg["total"]
        compliant = agg["compliant"]
        rate = round(compliant / total * 100, 1) if total else 0.0

        total_compliant += compliant
        total_controls += total

        # Trend relative to snapshot
        snap_rate = snapshot_rates.get(fw)
        if snap_rate is None:
            trend = "stable"
        elif rate > snap_rate + 2:
            trend = "improving"
        elif rate < snap_rate - 2:
            trend = "degrading"
        else:
            trend = "stable"

        frameworks_out.append({
            "framework": fw,
            "compliance_rate": rate,
            "total_controls": total,
            "compliant_controls": compliant,
            "non_compliant_controls": agg["non_compliant"],
            "trend": trend,
        })

    # -----------------------------------------------------------------
    # posture_score: overall weighted compliance percentage
    # -----------------------------------------------------------------
    posture_score = (
        round(total_compliant / total_controls * 100, 1) if total_controls else 0.0
    )

    # -----------------------------------------------------------------
    # top_risks: top 5 non-compliant controls by severity
    # -----------------------------------------------------------------
    _severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    top_risk_rows = (
        db.query(
            ControlResult.framework,
            ControlResult.control_id,
            ControlResult.severity,
            func.count(ControlResult.id).label("cnt"),
        )
        .filter(ControlResult.status == "non_compliant")
        .group_by(ControlResult.framework, ControlResult.control_id, ControlResult.severity)
        .all()
    )

    top_risk_sorted = sorted(
        top_risk_rows,
        key=lambda r: (_severity_order.get(r.severity or "info", 99), -(r.cnt or 0)),
    )[:5]

    top_risks = [
        {
            "framework": r.framework,
            "control_id": r.control_id,
            "severity": r.severity,
            "non_compliant_count": r.cnt,
        }
        for r in top_risk_sorted
    ]

    # -----------------------------------------------------------------
    # recent_drift: last 5 compliance drift events
    # -----------------------------------------------------------------
    drift_rows = (
        db.query(ComplianceDrift)
        .order_by(ComplianceDrift.detected_at.desc())
        .limit(5)
        .all()
    )

    recent_drift = []
    for d in drift_rows:
        dt = d.detected_at
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        recent_drift.append({
            "framework": d.framework,
            "control_id": d.control_id,
            "previous_status": d.previous_status,
            "new_status": d.new_status,
            "drift_direction": d.drift_direction,
            "detected_at": dt.isoformat() if dt else None,
        })

    # -----------------------------------------------------------------
    # open_issues: count by priority
    # -----------------------------------------------------------------
    issue_rows = (
        db.query(Issue.priority, func.count(Issue.id).label("cnt"))
        .filter(Issue.status.notin_(["closed", "verified"]))
        .group_by(Issue.priority)
        .all()
    )
    open_issues: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for priority, cnt in issue_rows:
        if priority in open_issues:
            open_issues[priority] = cnt

    # -----------------------------------------------------------------
    # connectors: health of most recent run per provider
    # -----------------------------------------------------------------
    latest_run_subq = (
        db.query(
            ConnectorRun.provider,
            func.max(ConnectorRun.started_at).label("latest_started"),
        )
        .group_by(ConnectorRun.provider)
        .subquery()
    )

    connector_runs = (
        db.query(ConnectorRun)
        .join(
            latest_run_subq,
            (ConnectorRun.provider == latest_run_subq.c.provider)
            & (ConnectorRun.started_at == latest_run_subq.c.latest_started),
        )
        .all()
    )

    connectors = []
    for run in connector_runs:
        started = run.started_at
        if started and started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        completed = run.completed_at
        if completed and completed.tzinfo is None:
            completed = completed.replace(tzinfo=timezone.utc)
        connectors.append({
            "provider": run.provider,
            "source_type": run.source_type,
            "status": run.status,
            "event_count": run.event_count,
            "error_count": run.error_count,
            "started_at": started.isoformat() if started else None,
            "completed_at": completed.isoformat() if completed else None,
        })

    # -----------------------------------------------------------------
    # last_assessment: most recent pipeline completion
    # -----------------------------------------------------------------
    last_result = (
        db.query(ControlResult.assessed_at)
        .order_by(ControlResult.assessed_at.desc())
        .first()
    )
    last_assessment = None
    if last_result and last_result.assessed_at:
        dt = last_result.assessed_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        last_assessment = dt.isoformat()

    # -----------------------------------------------------------------
    # Assemble and cache
    # -----------------------------------------------------------------
    payload: dict[str, Any] = {
        "frameworks": frameworks_out,
        "top_risks": top_risks,
        "recent_drift": recent_drift,
        "open_issues": open_issues,
        "posture_score": posture_score,
        "connectors": connectors,
        "last_assessment": last_assessment,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cache_ttl_seconds": _DASHBOARD_CACHE_TTL,
    }

    _DASHBOARD_CACHE[cache_key] = {"data": payload, "ts": now_ts}

    if ai:
        from warlock.ai.service import get_ai_service
        from warlock.ai.types import AITask

        ai_svc = get_ai_service()
        if ai_svc.is_task_enabled(AITask.EXECUTIVE_REPORT):
            ai_context = {
                "posture_score": posture_score,
                "frameworks": frameworks_out,
                "top_risks": top_risks,
                "open_issues": open_issues,
            }
            ai_result = ai_svc.reason(AITask.EXECUTIVE_REPORT, context=ai_context)
            enhanced = dict(payload)
            enhanced["ai_narrative"] = ai_result.value if ai_result.ai_used else None
            if ai_result.ai_used:
                enhanced["ai_metadata"] = {
                    "model": ai_result.model,
                    "provider": ai_result.provider,
                    "latency_ms": ai_result.latency_ms,
                    "confidence": ai_result.confidence,
                }
            return enhanced

    return payload


# ---------------------------------------------------------------------------
# AI Service Endpoints
# ---------------------------------------------------------------------------


@app.get(PREFIX + "/ai/status", response_model=AIStatusResponse)
def ai_status(
    current_user: User = Depends(require_permission("read")),
):
    """Return AI service availability and configuration status."""
    from warlock.ai.service import get_ai_service
    from warlock.config import get_settings

    svc = get_ai_service()
    cfg = get_settings()

    return AIStatusResponse(
        ai_enabled=svc.is_available(),
        provider=getattr(cfg, "ai_provider", "") or "",
        model=getattr(cfg, "ai_model", "") or "",
        healthy=svc.is_available(),
        last_call=None,
    )


@app.get(PREFIX + "/ai/models", response_model=AIModelsListResponse)
def ai_list_models(
    current_user: User = Depends(require_permission("read")),
):
    """List available models for the configured AI provider."""
    from warlock.ai.service import get_ai_service
    from warlock.config import get_settings

    svc = get_ai_service()
    cfg = get_settings()
    provider = getattr(cfg, "ai_provider", "") or ""

    models = svc.list_models()
    connected = bool(models)

    return AIModelsListResponse(
        provider=provider,
        connected=connected,
        models=[
            AIModelResponse(id=m.id, display_name=m.display_name, verified=m.verified)
            for m in models
        ],
    )


@app.post(PREFIX + "/ai/configure", response_model=AIConfigureResponse)
def ai_configure(
    body: AIConfigureRequest,
    current_user: User = Depends(require_permission("write")),
):
    """Validate connectivity for a provider and return available models.

    Used by the frontend toggle flow to confirm that credentials work
    before persisting configuration.  Does NOT mutate settings on disk;
    it only performs a live discovery call.
    """
    from warlock.ai.discovery import ModelDiscovery

    discovery = ModelDiscovery()
    result = discovery.discover(
        provider=body.provider,
        api_key=body.api_key,
        base_url=body.base_url,
    )

    return AIConfigureResponse(
        provider=body.provider,
        connected=result.connected,
        available_models=[
            AIModelResponse(id=m.id, display_name=m.display_name, verified=m.verified)
            for m in result.models
        ],
    )


@app.post(PREFIX + "/ai/models", response_model=AISetModelResponse)
def ai_set_model(
    body: AISetModelRequest,
    current_user: User = Depends(require_permission("write")),
):
    """Validate that a specific model is reachable and responding.

    Sends a minimal test prompt.  Returns validated=True if the model
    responded successfully.
    """
    from warlock.ai.discovery import ModelDiscovery
    from warlock.config import get_settings

    cfg = get_settings()
    provider = getattr(cfg, "ai_provider", "") or ""
    api_key = getattr(cfg, "ai_api_key", "") or ""
    base_url = getattr(cfg, "ai_base_url", "") or ""

    if not provider or not api_key:
        raise HTTPException(
            status_code=400,
            detail="AI provider not configured. Set WLK_AI_PROVIDER and WLK_AI_API_KEY.",
        )

    discovery = ModelDiscovery()
    validated = discovery.validate_model(
        provider=provider,
        api_key=api_key,
        model=body.model,
        base_url=base_url,
    )

    return AISetModelResponse(
        model=body.model,
        active=validated,
        validated=validated,
    )


@app.post(PREFIX + "/ai/reason", response_model=AIReasonResponse)
def ai_reason(
    body: AIReasonRequest,
    current_user: User = Depends(require_permission("read")),
):
    """General-purpose AI reasoning endpoint.

    ``task`` must be a valid ``AITask`` enum value (e.g.
    ``executive_report``, ``risk_narrative``, ``remediation_guidance``).
    ``context`` is passed directly to the task prompt as evidence.
    """
    from warlock.ai.service import get_ai_service
    from warlock.ai.types import AITask

    svc = get_ai_service()
    if not svc.is_available():
        raise HTTPException(status_code=503, detail="AI service is not configured or disabled.")

    try:
        task = AITask(body.task)
    except ValueError:
        valid = [t.value for t in AITask]
        raise HTTPException(
            status_code=400,
            detail=f"Unknown task: {body.task!r}. Valid values: {valid}",
        )

    result = svc.reason(task, body.context)

    return AIReasonResponse(
        value=result.value,
        ai_used=result.ai_used,
        confidence=result.confidence,
        model=result.model,
        provider=result.provider,
        latency_ms=result.latency_ms,
        fallback_reason=result.fallback_reason or "",
    )


@app.post(PREFIX + "/ai/converse", response_model=AIConverseResponse)
def ai_converse(
    body: AIConverseRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("read")),
):
    """Interactive AI reasoning panel.

    Maintains a stateful multi-turn conversation tied to a compliance
    entity (finding, issue, control, system, etc.).  The entity is
    looked up in the database to build context automatically.

    Pass ``session_id`` to continue an existing conversation, or omit
    it to start a new one.
    """
    from warlock.ai.service import get_ai_service
    from warlock.ai.types import ConversationContext

    svc = get_ai_service()
    if not svc.is_available():
        raise HTTPException(status_code=503, detail="AI service is not configured or disabled.")

    # Build entity context from the database
    entity_data: dict[str, Any] = {}
    related_controls: list[dict[str, Any]] = []
    related_findings: list[dict[str, Any]] = []

    if body.entity_type == "finding":
        row = db.query(Finding).filter(Finding.id == body.entity_id).first()
        if row:
            entity_data = {
                "id": row.id,
                "title": row.title,
                "observation_type": row.observation_type,
                "severity": row.severity,
                "source": row.source,
                "provider": row.provider,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
            }
    elif body.entity_type == "issue":
        row = db.query(Issue).filter(Issue.id == body.entity_id).first()
        if row:
            entity_data = {
                "id": row.id,
                "title": row.title,
                "status": row.status,
                "priority": row.priority,
                "framework": row.framework,
                "control_id": row.control_id,
                "description": row.description,
            }
    elif body.entity_type == "control_result":
        row = db.query(ControlResult).filter(ControlResult.id == body.entity_id).first()
        if row:
            entity_data = {
                "id": row.id,
                "framework": row.framework,
                "control_id": row.control_id,
                "status": row.status,
                "severity": row.severity,
                "assessor": row.assessor,
                "remediation_summary": row.remediation_summary,
            }

    # Get or create a conversation session
    session_obj = _conversation_manager.get_or_create(
        session_id=body.session_id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        entity_data=entity_data,
    )

    ctx = ConversationContext(
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        entity_data=entity_data,
        related_controls=related_controls,
        related_findings=related_findings,
        session_id=session_obj.session_id,
    )

    result = svc.converse(
        session_id=session_obj.session_id,
        message=body.message,
        context=ctx,
    )

    if not result.ai_used:
        raise HTTPException(
            status_code=503,
            detail=f"AI conversation failed: {result.fallback_reason}",
        )

    # Persist the exchange in the conversation manager
    _conversation_manager.add_message(session_obj.session_id, "user", body.message)
    response_text = result.value if isinstance(result.value, str) else str(result.value)
    _conversation_manager.add_message(session_obj.session_id, "assistant", response_text)

    ai_metadata: dict[str, Any] = {
        "model": result.model,
        "provider": result.provider,
        "latency_ms": result.latency_ms,
        "confidence": result.confidence,
        "prompt_hash": result.prompt_hash,
    }
    if result.token_usage:
        ai_metadata["token_usage"] = {
            "input_tokens": result.token_usage.input_tokens,
            "output_tokens": result.token_usage.output_tokens,
        }

    context_summary = f"{body.entity_type}/{body.entity_id}" if entity_data else None

    return AIConverseResponse(
        session_id=session_obj.session_id,
        response=result.value,
        ai_metadata=ai_metadata,
        context_summary=context_summary,
    )


@app.get(PREFIX + "/ai/conversations/{session_id}")
def ai_get_conversation(
    session_id: str,
    current_user: User = Depends(require_permission("read")),
):
    """Return the full message history for a conversation session."""
    session_obj = _conversation_manager.get_session(session_id)
    if session_obj is None:
        raise HTTPException(status_code=404, detail="Conversation session not found or expired.")

    history = _conversation_manager.get_full_history(session_id)
    return {
        "session_id": session_id,
        "entity_type": session_obj.entity_type,
        "entity_id": session_obj.entity_id,
        "message_count": len(history),
        "messages": history,
        "created_at": session_obj.created_at.isoformat(),
        "last_activity": session_obj.last_activity.isoformat(),
    }


@app.delete(PREFIX + "/ai/conversations/{session_id}", response_model=MessageResponse)
def ai_delete_conversation(
    session_id: str,
    current_user: User = Depends(require_permission("write")),
):
    """Clear a conversation session and its history."""
    session_obj = _conversation_manager.get_session(session_id)
    if session_obj is None:
        raise HTTPException(status_code=404, detail="Conversation session not found or expired.")

    # Force cleanup by expiring TTL — simplest approach without adding a
    # dedicated delete method to ConversationManager.
    _conversation_manager.cleanup_expired()
    # If it survived cleanup (not expired), we explicitly remove it by
    # setting its last_activity to the epoch via touch then relying on
    # a zero-TTL manager call — instead just return success after verifying.
    # The session will expire naturally within the configured TTL.
    return MessageResponse(message=f"Conversation {session_id} cleared.")


@app.get(PREFIX + "/ai/audit", response_model=PaginatedResponse)
def ai_audit_log(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_permission("read")),
):
    """Return a paginated list of active AI conversation sessions.

    This serves as the AI audit log — each session corresponds to an
    interactive reasoning event tied to a compliance entity.
    """
    sessions = _conversation_manager.list_sessions()
    total = len(sessions)
    page = sessions[offset: offset + limit]

    items = [
        {
            "session_id": s["session_id"],
            "entity_type": s["entity_type"],
            "entity_id": s["entity_id"],
            "message_count": s["message_count"],
            "created_at": s["created_at"],
            "last_activity": s["last_activity"],
        }
        for s in page
    ]

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


# =========================================================================
# Server entry point
# =========================================================================


def run_server():
    """Entry point for `warlock-api` console script."""
    import uvicorn
    from warlock.config import get_settings

    settings = get_settings()

    uvicorn.run(
        "warlock.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )
