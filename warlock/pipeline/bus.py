"""In-process event bus. Swap to Redis Streams / Celery when you need async."""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

log = logging.getLogger(__name__)


@dataclass
class PipelineEvent:
    event_type: (
        str  # "raw_event.created", "finding.normalized", "finding.mapped", "control.assessed"
    )
    payload_id: str  # UUID of the entity that was created/changed
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))


Handler = Callable[[PipelineEvent], None]


class EventBus:
    """Simple synchronous pub/sub. Handlers run in the publisher's thread.

    Good enough for single-process pipeline execution. When you need to
    scale, replace this with Redis Streams or similar — the interface stays
    the same.

    Infrastructure status: this in-process bus is intentionally the default
    for development and single-process Lambda deployments. It currently has
    no production subscribers registered at startup; events are published by
    the pipeline orchestrator but only consumed if a caller explicitly calls
    subscribe() or subscribe_all(). This is not dead code -- the bus is
    extensible by design and serves as the integration point for future
    consumers (alerting, audit logging, webhooks, etc.). Production
    deployments that need async fan-out should use the drop-in backends in
    queue.py (RedisStreamBus, KafkaBus, SQSBus) without changing the
    orchestrator.
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._wildcard_handlers: list[Handler] = []

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Subscribe to a specific event type."""
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        """Subscribe to every event (useful for audit logging)."""
        self._wildcard_handlers.append(handler)

    def publish(self, event: PipelineEvent) -> None:
        """Publish an event. All matching handlers run synchronously."""
        for handler in self._wildcard_handlers:
            _safe_call(handler, event)
        for handler in self._handlers.get(event.event_type, []):
            _safe_call(handler, event)

    def clear(self) -> None:
        """Remove all subscriptions."""
        self._handlers.clear()
        self._wildcard_handlers.clear()


def _safe_call(handler: Handler, event: PipelineEvent) -> None:
    try:
        handler(event)
    except Exception:
        log.exception("Handler %s failed for event %s", handler.__name__, event.event_type)
        _record_dead_letter(event, handler)


def _record_dead_letter(event: PipelineEvent, handler: Handler) -> None:
    """Persist a failed event to the dead letter queue for later retry."""
    import traceback

    try:
        from warlock.db.engine import get_session
        from warlock.db.models import DeadLetterEntry

        error_msg = traceback.format_exc()
        with get_session() as session:
            entry = DeadLetterEntry(
                event_type=event.event_type,
                payload=event.metadata,
                error_message=f"{handler.__name__}: {error_msg[:2000]}",
                original_event_id=event.id,
            )
            session.add(entry)
    except Exception:
        log.exception("Failed to record dead letter entry for event %s", event.id)


# ---------------------------------------------------------------------------
# Auto-registration of subscribers at import time (#34)
# ---------------------------------------------------------------------------


def _register_default_subscribers(bus: "EventBus") -> None:
    """Register built-in subscribers when their config is present.

    Called once when a new EventBus is created (or by the queue factory).
    Subscribers are only registered when the relevant environment variables
    are set so that default test runs remain unaffected.
    """
    webhook_urls = os.environ.get("WLK_WEBHOOK_URLS", "").strip()
    if webhook_urls:
        from warlock.export.alerts import WebhookSubscriber

        subscriber = WebhookSubscriber()
        for event_type in ("finding.normalized", "control.assessed"):
            bus.subscribe(event_type, subscriber)
        log.info(
            "WebhookSubscriber registered for %d URL(s)",
            len([u for u in webhook_urls.split(",") if u.strip()]),
        )

    # Slack
    slack_url = os.environ.get("WLK_SLACK_WEBHOOK_URL", "").strip()
    if slack_url:
        from warlock.integrations.slack import SlackNotifier

        subscriber = SlackNotifier()
        for event_type in ("finding.normalized", "control.assessed"):
            bus.subscribe(event_type, subscriber)
        log.info("SlackNotifier registered")

    # PagerDuty
    pd_key = os.environ.get("WLK_PAGERDUTY_ROUTING_KEY", "").strip()
    if pd_key:
        from warlock.integrations.pagerduty import PagerDutyNotifier

        subscriber = PagerDutyNotifier()
        bus.subscribe("control.assessed", subscriber)
        log.info("PagerDutyNotifier registered")

    # Jira
    jira_url = os.environ.get("WLK_JIRA_BASE_URL", "").strip()
    if jira_url:
        from warlock.integrations.jira_integration import JiraNotifier

        subscriber = JiraNotifier()
        bus.subscribe("control.assessed", subscriber)
        log.info("JiraNotifier registered")

    # ServiceNow
    snow_instance = os.environ.get("WLK_SERVICENOW_INSTANCE", "").strip()
    if snow_instance:
        from warlock.integrations.servicenow_integration import ServiceNowNotifier

        subscriber = ServiceNowNotifier()
        bus.subscribe("control.assessed", subscriber)
        log.info("ServiceNowNotifier registered")

    # Email notifications
    email_enabled = os.environ.get("WLK_EMAIL_ENABLED", "").strip().lower()
    if email_enabled == "true":
        try:
            from warlock.integrations.email_notifications import EmailNotifier

            subscriber = EmailNotifier()
            bus.subscribe("control.assessed", subscriber)
            log.info("EmailNotifier registered")
        except Exception:
            log.exception("Failed to register EmailNotifier")

    # Audit event subscriber — wire when an external sink backend is configured.
    # Guards against default test runs by checking for WLK_AUDIT_SINK_BACKEND.
    # The "stdout" default is intentionally excluded because stdout is not a
    # useful bus-driven sink (AuditTrail.record() already handles that path).
    audit_backend = os.environ.get("WLK_AUDIT_SINK_BACKEND", "").strip().lower()
    if audit_backend and audit_backend != "stdout":
        try:
            from warlock.export.audit_sink import (
                AuditEventSubscriber,
                BatchShipper,
                create_sink_from_env,
            )

            sink = create_sink_from_env()
            shipper = BatchShipper(sink)
            subscriber = AuditEventSubscriber(shipper)
            bus.subscribe_all(subscriber)
            log.info(
                "AuditEventSubscriber registered with %s sink backend",
                audit_backend,
            )
        except Exception:
            log.exception(
                "Failed to register AuditEventSubscriber for backend %r — "
                "external audit shipping disabled",
                audit_backend,
            )
