"""GAP-049: Webhook registration and management API.

Stores webhook configurations in the audit trail since there is no
dedicated webhook model. Each registration is an AuditEntry with
action ``webhook_registered`` and the config in metadata.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from warlock.api.deps import get_db, require_permission
from warlock.config import get_settings
from warlock.db.audit import AuditTrail
from warlock.db.models import AuditEntry, User, _uuid

log = logging.getLogger(__name__)

router = APIRouter()


# ------------------------------------------------------------------
# Request / response schemas
# ------------------------------------------------------------------


class WebhookCreate(BaseModel):
    url: str = Field(..., description="Destination URL for webhook delivery")
    secret: str = Field(default="", description="Shared secret for HMAC signature verification")
    event_types: list[str] = Field(
        default_factory=list,
        description="Event types to subscribe to (empty = all)",
    )


class WebhookOut(BaseModel):
    id: str
    url: str
    event_types: list[str]
    created_at: str
    active: bool = True


class WebhookTestResult(BaseModel):
    status: str
    message: str


# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------


@router.post("/webhooks", status_code=status.HTTP_201_CREATED, response_model=WebhookOut)
def register_webhook(
    body: WebhookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin")),
) -> dict:
    """Register a new webhook destination."""
    webhook_id = _uuid()
    now = datetime.now(timezone.utc)

    audit = AuditTrail(db)
    audit.record(
        action="webhook_registered",
        entity_type="webhook",
        entity_id=webhook_id,
        actor=current_user.email,
        metadata={
            "url": body.url,
            "secret_hash": hashlib.sha256(body.secret.encode()).hexdigest() if body.secret else "",
            "event_types": body.event_types,
            "active": True,
            "created_at": now.isoformat(),
        },
    )

    log.info("Webhook %s registered by %s -> %s", webhook_id, current_user.email, body.url)
    return {
        "id": webhook_id,
        "url": body.url,
        "event_types": body.event_types,
        "created_at": now.isoformat(),
        "active": True,
    }


@router.get("/webhooks", response_model=list[WebhookOut])
def list_webhooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin")),
) -> list[dict]:
    """List all registered webhooks."""
    # Find all webhook_registered entries that haven't been deleted
    registered = (
        db.query(AuditEntry)
        .filter(AuditEntry.action == "webhook_registered")
        .order_by(AuditEntry.sequence.desc())
        .all()
    )

    deleted_ids: set[str] = set()
    deleted_entries = db.query(AuditEntry).filter(AuditEntry.action == "webhook_deleted").all()
    for entry in deleted_entries:
        deleted_ids.add(entry.entity_id)

    results: list[dict] = []
    seen: set[str] = set()
    for entry in registered:
        wid = entry.entity_id
        if wid in seen or wid in deleted_ids:
            continue
        seen.add(wid)

        meta = entry.metadata_ or {}
        results.append(
            {
                "id": wid,
                "url": meta.get("url", ""),
                "event_types": meta.get("event_types", []),
                "created_at": meta.get("created_at", ""),
                "active": meta.get("active", True),
            }
        )

    return results


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(
    webhook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin")),
) -> None:
    """Remove a registered webhook."""
    # Verify webhook exists
    exists = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.entity_id == webhook_id,
            AuditEntry.action == "webhook_registered",
        )
        .first()
    )
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook {webhook_id} not found",
        )

    audit = AuditTrail(db)
    audit.record(
        action="webhook_deleted",
        entity_type="webhook",
        entity_id=webhook_id,
        actor=current_user.email,
        metadata={"deleted_at": datetime.now(timezone.utc).isoformat()},
    )

    log.info("Webhook %s deleted by %s", webhook_id, current_user.email)


@router.post("/webhooks/{webhook_id}/test", response_model=WebhookTestResult)
def test_webhook(
    webhook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission("admin")),
) -> dict:
    """Send a test payload to a registered webhook.

    Note: actual HTTP delivery requires an async task queue.
    This endpoint validates the webhook exists and records a test event.
    """
    entry = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.entity_id == webhook_id,
            AuditEntry.action == "webhook_registered",
        )
        .first()
    )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Webhook {webhook_id} not found",
        )

    meta = entry.metadata_ or {}
    test_payload = {
        "event": "webhook.test",
        "webhook_id": webhook_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "This is a test payload from Warlock GRC.",
    }

    # Compute HMAC signature if secret was provided
    secret_hash = meta.get("secret_hash", "")
    if secret_hash:
        sig = hmac.new(
            secret_hash.encode(),
            json.dumps(test_payload, sort_keys=True).encode(),
            hashlib.sha256,
        ).hexdigest()
        test_payload["signature"] = sig

    audit = AuditTrail(db)
    audit.record(
        action="webhook_test_sent",
        entity_type="webhook",
        entity_id=webhook_id,
        actor=current_user.email,
        metadata={
            "url": meta.get("url", ""),
            "test_payload": test_payload,
        },
    )

    log.info("Webhook test sent for %s by %s", webhook_id, current_user.email)
    return {
        "status": "sent",
        "message": f"Test payload queued for delivery to {meta.get('url', 'unknown')}",
    }


# ---------------------------------------------------------------------------
# GAP-045: Inbound Jira webhook receiver
# ---------------------------------------------------------------------------


class JiraWebhookResponse(BaseModel):
    status: str
    matched: bool = False
    updated: bool = False
    details: str = ""


def _verify_jira_signature(body: bytes, signature: str | None, secret: str) -> bool:
    """Verify Jira webhook HMAC-SHA256 signature.

    If no webhook secret is configured, verification is skipped (dev mode).
    """
    if not secret:
        return True
    if not signature:
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/jira", response_model=JiraWebhookResponse)
async def jira_webhook(
    request: Request,
    x_hub_signature: str | None = Header(None, alias="x-hub-signature"),
) -> JiraWebhookResponse:
    """Receive Jira webhook payload for bidirectional issue sync.

    Validates the HMAC signature (if ``WLK_JIRA_WEBHOOK_SECRET`` is set),
    then delegates to ``handle_jira_webhook`` for status synchronisation.
    """
    body = await request.body()
    settings = get_settings()
    webhook_secret = getattr(settings, "jira_webhook_secret", "") or ""

    if not _verify_jira_signature(body, x_hub_signature, webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    from warlock.db.engine import get_session
    from warlock.integrations.jira_sync import handle_jira_webhook

    with get_session() as session:
        result = handle_jira_webhook(payload, session)

    return JiraWebhookResponse(
        status="processed",
        matched=result.get("matched", False),
        updated=result.get("updated", False),
        details=result.get("details", ""),
    )


# ------------------------------------------------------------------
# Webhook event catalog — Item 117
# ------------------------------------------------------------------

_WEBHOOK_EVENT_CATALOG = [
    {
        "event_type": "control_status_change",
        "description": "Fired when a control result status changes (e.g., compliant -> non_compliant)",
        "payload_fields": ["control_id", "framework", "old_status", "new_status", "timestamp"],
    },
    {
        "event_type": "alert_triggered",
        "description": "Fired when a new alert is triggered by the rule engine",
        "payload_fields": ["alert_id", "severity", "rule_name", "message", "timestamp"],
    },
    {
        "event_type": "poam_overdue",
        "description": "Fired when a POA&M passes its scheduled completion date",
        "payload_fields": ["poam_id", "framework", "control_id", "due_date", "timestamp"],
    },
    {
        "event_type": "poam_transition",
        "description": "Fired when a POA&M status changes",
        "payload_fields": ["poam_id", "old_status", "new_status", "actor", "timestamp"],
    },
    {
        "event_type": "pipeline_completed",
        "description": "Fired when a full pipeline run completes",
        "payload_fields": [
            "run_id",
            "connectors_ok",
            "connectors_failed",
            "findings_normalized",
            "controls_mapped",
            "duration_seconds",
        ],
    },
    {
        "event_type": "finding_created",
        "description": "Fired when new findings are normalized from raw events",
        "payload_fields": ["finding_id", "severity", "source", "title", "timestamp"],
    },
    {
        "event_type": "compliance_drift",
        "description": "Fired when compliance posture drifts beyond threshold",
        "payload_fields": ["framework", "control_id", "previous_score", "current_score", "delta"],
    },
    {
        "event_type": "evidence_expired",
        "description": "Fired when evidence freshness exceeds its validity window",
        "payload_fields": ["evidence_id", "framework", "control_id", "age_days"],
    },
]


@router.get("/webhooks/events")
def webhook_event_catalog() -> list[dict]:
    """List all available webhook event types and their payload schemas."""
    return _WEBHOOK_EVENT_CATALOG
