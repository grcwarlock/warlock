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
from warlock.utils.crypto import decrypt_field, encrypt_field

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
    current_user: User = Depends(require_permission("manage_users")),
) -> dict:
    """Register a new webhook destination."""
    # SEC-C13: refuse to persist a webhook URL that the safety helper
    # would reject. Without this, a caller with ``manage_users`` permission
    # can register ``http://169.254.169.254/...`` and the delivery worker
    # will POST signed pipeline events (with the HMAC secret oracle) to
    # the metadata service. Validation runs BEFORE persistence — there is
    # no "saved-but-disabled" state that could later be re-enabled by
    # toggling a flag.
    from warlock.utils.url_safety import UnsafeURLError, validate_outbound_url

    try:
        validate_outbound_url(body.url)
    except UnsafeURLError as exc:
        raise HTTPException(status_code=400, detail=f"Unsafe webhook URL: {exc}")

    webhook_id = _uuid()
    now = datetime.now(timezone.utc)

    # F16/F27: Persist the secret ENCRYPTED (Fernet) so the delivery worker
    # can compute a real HMAC. Never store a hash of the secret — short
    # secrets would be offline-brute-forceable. Encryption requires
    # WLK_ENCRYPTION_KEY in production; falls back to keystream-XOR with
    # WLK_JWT_SECRET in dev (still not browse-able from a DB dump).
    secret_ciphertext = ""
    if body.secret:
        try:
            secret_ciphertext = encrypt_field(body.secret)
        except Exception as exc:
            log.error("Failed to encrypt webhook secret: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="Encryption is not configured — set WLK_ENCRYPTION_KEY",
            )

    audit = AuditTrail(db)
    audit.record(
        action="webhook_registered",
        entity_type="webhook",
        entity_id=webhook_id,
        actor=current_user.email,
        metadata={
            "url": body.url,
            "secret_encrypted": secret_ciphertext,
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
    current_user: User = Depends(require_permission("manage_users")),
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
    current_user: User = Depends(require_permission("manage_users")),
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
    current_user: User = Depends(require_permission("manage_users")),
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

    # F16: Compute a REAL HMAC signature using the decrypted secret.
    # Receivers compute the same HMAC with their stored secret to verify.
    secret_ct = meta.get("secret_encrypted", "")
    if secret_ct:
        try:
            secret = decrypt_field(secret_ct)
        except Exception as exc:
            log.error("Failed to decrypt webhook secret for %s: %s", webhook_id, exc)
            raise HTTPException(
                status_code=500,
                detail="Webhook secret could not be decrypted — re-register the webhook",
            )
        sig = hmac.new(
            secret.encode(),
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

    Callers MUST handle the "no secret configured" case separately — this
    function returns False when the secret is missing (fail-closed). Bypass
    for development happens in the route handler (finding F22).

    N9 fix: strip common header prefixes (``sha256=``, ``v1=``) so Atlassian's
    ``X-Hub-Signature: sha256=<hex>`` and the JIRA Cloud ``Atlassian-Webhook-Identifier``
    style both verify. Without this strip, every legitimate Jira call failed
    verification and operators ended up disabling signing.
    """
    if not secret:
        return False
    if not signature:
        return False
    sig_value = signature.strip()
    for prefix in ("sha256=", "v1=", "sha1="):
        if sig_value.startswith(prefix):
            sig_value = sig_value[len(prefix) :]
            break
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_value)


@router.post("/jira", response_model=JiraWebhookResponse)
async def jira_webhook(
    request: Request,
    x_hub_signature: str | None = Header(None, alias="x-hub-signature"),
) -> JiraWebhookResponse:
    """Receive Jira webhook payload for bidirectional issue sync.

    Validates the HMAC signature. In production/staging, a webhook secret
    MUST be configured (``WLK_JIRA_WEBHOOK_SECRET``) or the endpoint refuses
    requests. Development mode allows unsigned payloads for iteration.
    """
    body = await request.body()
    settings = get_settings()
    webhook_secret = getattr(settings, "jira_webhook_secret", "") or ""

    if not webhook_secret:
        if settings.env != "development":
            raise HTTPException(
                status_code=503,
                detail="Jira webhook not configured — WLK_JIRA_WEBHOOK_SECRET required",
            )
        # Development only: accept without signature verification
    elif not _verify_jira_signature(body, x_hub_signature, webhook_secret):
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
