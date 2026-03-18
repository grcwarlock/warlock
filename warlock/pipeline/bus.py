"""In-process event bus. Swap to Redis Streams / Celery when you need async."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

log = logging.getLogger(__name__)


@dataclass
class PipelineEvent:
    event_type: str          # "raw_event.created", "finding.normalized", "finding.mapped", "control.assessed"
    payload_id: str          # UUID of the entity that was created/changed
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))


Handler = Callable[[PipelineEvent], None]


class EventBus:
    """Simple synchronous pub/sub. Handlers run in the publisher's thread.

    Good enough for single-process pipeline execution. When you need to
    scale, replace this with Redis Streams or similar — the interface stays
    the same.
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
