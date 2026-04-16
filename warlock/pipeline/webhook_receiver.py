"""Real-time streaming / webhook ingestion endpoint.

Accepts push events from CloudTrail, GuardDuty, SNS, and generic JSON
payloads. Validates HMAC signatures (configurable per source) and queues
received events for pipeline processing.

Item 60: POST /api/v1/ingest/webhook
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

router = APIRouter()


# ------------------------------------------------------------------
# Request / response schemas
# ------------------------------------------------------------------


class WebhookPayload(BaseModel):
    """Generic webhook payload envelope."""

    source: str = Field(default="generic", description="Event source identifier")
    event_type: str = Field(default="", description="Event type hint")
    data: dict = Field(default_factory=dict, description="Event payload")
    timestamp: str = Field(default="", description="Event timestamp (ISO 8601)")


class IngestResult(BaseModel):
    """Response from webhook ingestion."""

    event_id: str
    status: str
    source: str
    queued: bool


# ------------------------------------------------------------------
# HMAC signature validation
# ------------------------------------------------------------------

_SOURCE_SECRETS: dict[str, str] = {}


def _load_source_secrets() -> dict[str, str]:
    """Load per-source HMAC secrets from config.

    Secrets are configured via WLK_WEBHOOK_SECRETS as a JSON dict:
    {"cloudtrail": "secret1", "guardduty": "secret2"}
    """
    global _SOURCE_SECRETS
    if _SOURCE_SECRETS:
        return _SOURCE_SECRETS

    from warlock.config import get_settings

    settings = get_settings()
    raw = getattr(settings, "webhook_secrets", "{}")
    if raw:
        try:
            _SOURCE_SECRETS = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            log.warning("Invalid WLK_WEBHOOK_SECRETS format — HMAC validation disabled")
            _SOURCE_SECRETS = {}
    return _SOURCE_SECRETS


def _validate_hmac(body: bytes, signature: str | None, source: str) -> bool:
    """Validate HMAC-SHA256 signature for the given source.

    Returns True only if a secret is configured AND the signature matches.
    Outside development, requests from sources without a configured secret
    are REJECTED (finding F7). In development, they pass to keep iteration fast.
    """
    from warlock.config import get_settings

    secrets = _load_source_secrets()
    secret = secrets.get(source)
    if not secret:
        if get_settings().env == "development":
            log.warning(
                "Webhook source %r has no configured HMAC secret — allowing in development",
                source,
            )
            return True
        log.warning(
            "Webhook source %r has no configured HMAC secret in env=%s — rejecting",
            source,
            get_settings().env,
        )
        return False

    if not signature:
        return False  # Secret configured but no signature provided

    # Strip common prefixes: "sha256=", "v1=", etc.
    sig_value = signature
    for prefix in ("sha256=", "v1=", "sha1="):
        if sig_value.startswith(prefix):
            sig_value = sig_value[len(prefix) :]
            break

    expected = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, sig_value)


# ------------------------------------------------------------------
# SNS message parsing
# ------------------------------------------------------------------


def _parse_sns_envelope(data: dict) -> dict:
    """Extract the inner message from an SNS notification envelope."""
    if data.get("Type") == "SubscriptionConfirmation":
        log.info(
            "SNS subscription confirmation received — SubscribeURL: %s",
            data.get("SubscribeURL", ""),
        )
        return {"_sns_confirmation": True, "subscribe_url": data.get("SubscribeURL", "")}

    if data.get("Type") == "Notification":
        message = data.get("Message", "")
        try:
            return json.loads(message)
        except (json.JSONDecodeError, TypeError):
            return {"raw_message": message}

    return data


def _detect_source(data: dict) -> str:
    """Auto-detect the event source from payload structure."""
    # CloudTrail
    if "Records" in data and isinstance(data["Records"], list):
        first = data["Records"][0] if data["Records"] else {}
        if "eventSource" in first:
            return "cloudtrail"

    # GuardDuty
    if "detail-type" in data and "GuardDuty" in str(data.get("detail-type", "")):
        return "guardduty"
    if data.get("detail", {}).get("type", "").startswith("Recon:") or data.get("detail", {}).get(
        "type", ""
    ).startswith("UnauthorizedAccess:"):
        return "guardduty"

    # SNS envelope
    if data.get("Type") in ("Notification", "SubscriptionConfirmation"):
        return "sns"

    return "generic"


# ------------------------------------------------------------------
# Endpoint
# ------------------------------------------------------------------


@router.post(
    "/ingest/webhook",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestResult,
    summary="Ingest push events via webhook",
)
async def ingest_webhook(
    request: Request,
    x_webhook_signature: str | None = Header(None, alias="X-Webhook-Signature"),
    x_hub_signature_256: str | None = Header(None, alias="X-Hub-Signature-256"),
    x_amz_sns_message_type: str | None = Header(None, alias="X-Amz-Sns-Message-Type"),
) -> dict:
    """Receive push events from CloudTrail, GuardDuty, SNS, or generic JSON.

    Validates HMAC signature if a secret is configured for the detected source.
    Queues the event for pipeline processing.
    """
    body = await request.body()

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body must be valid JSON",
        )

    # Detect source
    source = _detect_source(data)

    # Handle SNS envelopes
    if source == "sns" or x_amz_sns_message_type:
        data = _parse_sns_envelope(data)
        if data.get("_sns_confirmation"):
            return {
                "event_id": str(uuid4()),
                "status": "sns_confirmation_received",
                "source": "sns",
                "queued": False,
            }
        # Re-detect source from unwrapped message
        source = _detect_source(data) if source == "sns" else source

    # Validate HMAC signature
    signature = x_webhook_signature or x_hub_signature_256
    if not _validate_hmac(body, signature, source):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # Build event for pipeline queue
    event_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()

    queued = _queue_event(
        event_id=event_id,
        source=source,
        data=data,
        received_at=now,
    )

    log.info("Webhook event ingested: id=%s source=%s queued=%s", event_id, source, queued)

    return {
        "event_id": event_id,
        "status": "accepted",
        "source": source,
        "queued": queued,
    }


def _queue_event(event_id: str, source: str, data: dict, received_at: str) -> bool:
    """Queue an ingested event for pipeline processing.

    Uses the configured queue backend (memory, Redis, Kafka, SQS).
    Falls back to direct DB insertion if no queue is available.
    """
    try:
        from warlock.config import get_settings

        settings = get_settings()

        # Build raw event record
        event_record = {
            "id": event_id,
            "source": source,
            "event_type": f"webhook:{source}",
            "raw_data": data,
            "received_at": received_at,
        }

        if settings.queue_backend != "memory":
            # Use configured queue backend for async processing
            try:
                from warlock.pipeline.queue import get_queue

                queue = get_queue()
                queue.publish("webhook_events", json.dumps(event_record, default=str))
                return True
            except Exception as exc:
                log.warning("Queue publish failed, falling back to direct insert: %s", exc)

        # Direct insert into raw_events table
        from warlock.db.engine import get_session
        from warlock.db.models import RawEvent

        with get_session() as session:
            raw = RawEvent(
                id=event_id,
                source=source,
                event_type=f"webhook:{source}",
                raw_data=data,
                collected_at=datetime.now(timezone.utc),
            )
            session.add(raw)

        return True

    except Exception as exc:
        log.error("Failed to queue webhook event %s: %s", event_id, exc)
        return False
