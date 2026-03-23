"""AI service routes: status, models, reasoning, conversations, audit."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission
from warlock.api.routers.schemas import MessageResponse, PaginatedResponse
from warlock.db.models import User
from warlock.db.repository import get_repos

router = APIRouter()
log = logging.getLogger(__name__)


# Module-level ConversationManager instance (shared across requests within a
# single worker process). This is intentionally per-worker — the conversation
# state is complex (multi-turn message history, entity context) and already
# bounded by TTL + session caps. Moving to Redis would require serializing the
# full ConversationSession graph, which is a larger refactor. See roadmap #132.
from warlock.ai.conversation import ConversationManager as _ConversationManager  # noqa: E402

_conversation_manager = _ConversationManager()


# ---------------------------------------------------------------------------
# Models
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/ai/status", response_model=AIStatusResponse)
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


@router.get("/ai/models", response_model=AIModelsListResponse)
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


@router.post("/ai/configure", response_model=AIConfigureResponse)
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


@router.post("/ai/models", response_model=AISetModelResponse)
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


@router.post("/ai/reason", response_model=AIReasonResponse)
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


@router.post("/ai/converse", response_model=AIConverseResponse)
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
    repos = get_repos(db)
    entity_data: dict[str, Any] = {}
    related_controls: list[dict[str, Any]] = []
    related_findings: list[dict[str, Any]] = []

    if body.entity_type == "finding":
        row = repos.findings.get(body.entity_id)
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
        row = repos.issues.get(body.entity_id)
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
        row = repos.control_results.get(body.entity_id)
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

    # Get or create a conversation session (H-12: scoped to current user)
    session_obj = _conversation_manager.get_or_create(
        session_id=body.session_id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        entity_data=entity_data,
        user_id=current_user.id,
    )
    if session_obj is None:
        raise HTTPException(status_code=404, detail="Conversation session not found or expired.")

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


@router.get("/ai/conversations/{session_id}")
def ai_get_conversation(
    session_id: str,
    current_user: User = Depends(require_permission("read")),
):
    """Return the full message history for a conversation session."""
    # H-12: Only return sessions owned by the requesting user (404 prevents enumeration)
    session_obj = _conversation_manager.get_session(session_id, user_id=current_user.id)
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


@router.delete("/ai/conversations/{session_id}", response_model=MessageResponse)
def ai_delete_conversation(
    session_id: str,
    current_user: User = Depends(require_permission("write")),
):
    """Delete a conversation session and its history."""
    # H-12: Verify ownership before deletion (404 prevents enumeration)
    if not _conversation_manager.delete_session(session_id, user_id=current_user.id):
        raise HTTPException(status_code=404, detail="Conversation session not found or expired.")

    log.info("Conversation session %s deleted by user %s", session_id, current_user.id)
    return MessageResponse(message=f"Conversation {session_id} deleted.")


@router.get("/ai/audit", response_model=PaginatedResponse)
def ai_audit_log(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_permission("read")),
):
    """Return a paginated list of active AI conversation sessions.

    This serves as the AI audit log -- each session corresponds to an
    interactive reasoning event tied to a compliance entity.

    H-12: Non-admin users only see their own sessions.
    """
    # Admins see all sessions; everyone else sees only their own
    filter_user_id = "" if current_user.role == "admin" else current_user.id
    sessions = _conversation_manager.list_sessions(user_id=filter_user_id)
    total = len(sessions)
    page = sessions[offset : offset + limit]

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
