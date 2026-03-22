"""Domain event bus with cascade safety."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

from warlock.domains.base import DomainEvent

log = logging.getLogger(__name__)

DomainHandler = Callable[[DomainEvent], list[DomainEvent] | None]


class DomainEventBus:
    """Pub/sub for domain events with cascade support.

    Handlers may return new DomainEvents to trigger cascades.
    Cascade safety: max depth, deduplication within a correlation.
    """

    def __init__(self, max_cascade_depth: int = 5) -> None:
        self._handlers: dict[str, list[DomainHandler]] = defaultdict(list)
        self._wildcard_handlers: list[DomainHandler] = []
        self._max_depth = max_cascade_depth
        self._seen: set[tuple[str, str, str]] = set()

    def subscribe(self, event_type: str, handler: DomainHandler) -> None:
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: DomainHandler) -> None:
        self._wildcard_handlers.append(handler)

    def publish(self, event: DomainEvent) -> None:
        dedup_key = (event.correlation_id, event.event_type, event.entity_id)
        self._seen.add(dedup_key)
        self._dispatch(event, depth=0)

    def publish_cascade(self, event: DomainEvent, correlation_id: str, depth: int) -> None:
        """Publish an event as part of an ongoing correlation, with deduplication.

        Skips dispatch if the same (correlation_id, event_type, entity_id) was
        already handled in a previous publish or publish_cascade call.
        """
        event.correlation_id = correlation_id
        dedup_key = (correlation_id, event.event_type, event.entity_id)
        if dedup_key in self._seen:
            log.debug(
                "Dedup: skipping %s/%s in correlation %s",
                event.event_type,
                event.entity_id,
                correlation_id,
            )
            return
        self._seen.add(dedup_key)
        self._dispatch(event, depth=depth)

    def _dispatch(self, event: DomainEvent, depth: int) -> None:
        if depth >= self._max_depth:
            log.warning(
                "Cascade depth %d reached for %s (correlation=%s). Stopping.",
                depth,
                event.event_type,
                event.correlation_id,
            )
            return

        cascade_events: list[DomainEvent] = []

        for handler in self._wildcard_handlers:
            cascade_events.extend(self._safe_call(handler, event))

        for handler in self._handlers.get(event.event_type, []):
            cascade_events.extend(self._safe_call(handler, event))

        for cascade_event in cascade_events:
            cascade_event.correlation_id = event.correlation_id
            self._dispatch(cascade_event, depth + 1)

    def _safe_call(self, handler: DomainHandler, event: DomainEvent) -> list[DomainEvent]:
        try:
            result = handler(event)
            return result if result else []
        except Exception:
            log.exception("Domain handler failed for event %s", event.event_type)
            return []

    def clear(self) -> None:
        self._handlers.clear()
        self._wildcard_handlers.clear()
        self._seen.clear()
