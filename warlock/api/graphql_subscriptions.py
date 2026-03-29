"""GraphQL subscription support for real-time compliance events.

Uses Strawberry GraphQL's subscription support wired through the
WebSocket EventBus defined in ``warlock.api.websocket``.

Event types mirror the WebSocket event bus:
  - complianceDriftDetected
  - alertTriggered
  - findingCreated
  - poamTransitioned
  - pipelineCompleted
  - controlStatusChanged
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

log = logging.getLogger(__name__)

try:
    import strawberry

    _HAS_STRAWBERRY = True
except ImportError:
    _HAS_STRAWBERRY = False
    log.info("strawberry-graphql not installed -- GraphQL subscriptions unavailable")


# ---------------------------------------------------------------------------
# Subscription event types
# ---------------------------------------------------------------------------

SUBSCRIPTION_TYPES = [
    "complianceDriftDetected",
    "alertTriggered",
    "findingCreated",
    "poamTransitioned",
    "pipelineCompleted",
    "controlStatusChanged",
]

# Map camelCase subscription names -> WebSocket event bus names
_EVENT_MAP: dict[str, str] = {
    "complianceDriftDetected": "compliance_drift",
    "alertTriggered": "alert",
    "findingCreated": "finding_created",
    "poamTransitioned": "poam_transition",
    "pipelineCompleted": "pipeline_completed",
    "controlStatusChanged": "control_status_change",
}

_REVERSE_MAP: dict[str, str] = {v: k for k, v in _EVENT_MAP.items()}


# ---------------------------------------------------------------------------
# Strawberry types (only defined when strawberry is available)
# ---------------------------------------------------------------------------

if _HAS_STRAWBERRY:

    @strawberry.type
    class ComplianceEvent:
        """A real-time compliance event delivered via GraphQL subscription."""

        event_type: str
        timestamp: str
        source: str = ""
        entity_id: str = ""
        framework: str = ""
        severity: str = ""
        message: str = ""
        data: strawberry.scalars.JSON | None = None  # type: ignore[name-defined]

    @strawberry.type
    class Subscription:
        """GraphQL subscriptions for compliance event streaming."""

        @strawberry.subscription
        async def compliance_events(
            self,
            event_types: list[str] | None = None,
            framework: str | None = None,
        ) -> AsyncGenerator[ComplianceEvent, None]:
            """Subscribe to real-time compliance events.

            Args:
                event_types: Filter to specific event types (default: all).
                    Valid values: complianceDriftDetected, alertTriggered,
                    findingCreated, poamTransitioned, pipelineCompleted,
                    controlStatusChanged.
                framework: Filter to events for a specific framework.

            Yields:
                ComplianceEvent objects as they occur.
            """
            from warlock.api.websocket import get_event_bus

            bus = get_event_bus()
            queue = bus.subscribe()

            # Resolve requested event type filters to internal names
            allowed_internal: set[str] | None = None
            if event_types:
                allowed_internal = set()
                for et in event_types:
                    internal = _EVENT_MAP.get(et, et)
                    allowed_internal.add(internal)

            try:
                while True:
                    try:
                        message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    except asyncio.TimeoutError:
                        # Send keepalive as a no-op; GraphQL-WS handles pings
                        continue

                    msg_type = message.get("event_type", "")
                    msg_data = message.get("data", {})

                    # Apply event type filter
                    if allowed_internal and msg_type not in allowed_internal:
                        continue

                    # Apply framework filter
                    if framework:
                        event_fw = msg_data.get("framework", "")
                        if event_fw and event_fw != framework:
                            continue

                    gql_type = _REVERSE_MAP.get(msg_type, msg_type)

                    yield ComplianceEvent(
                        event_type=gql_type,
                        timestamp=message.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        source=msg_data.get("source", ""),
                        entity_id=msg_data.get("entity_id", msg_data.get("id", "")),
                        framework=msg_data.get("framework", ""),
                        severity=msg_data.get("severity", ""),
                        message=msg_data.get("message", msg_data.get("description", "")),
                        data=msg_data,
                    )
            finally:
                bus.unsubscribe(queue)

    def get_subscription_schema() -> Any:
        """Build and return the Strawberry schema with subscription support.

        Returns None if strawberry is not installed.
        """

        # Minimal query type required by Strawberry
        @strawberry.type
        class Query:
            @strawberry.field
            def health(self) -> str:
                return "ok"

        return strawberry.Schema(query=Query, subscription=Subscription)

else:

    def get_subscription_schema() -> Any:  # type: ignore[misc]
        """Strawberry not installed -- returns None."""
        return None


def publish_compliance_event(
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Convenience helper to publish a compliance event to the WebSocket bus.

    This is fire-and-forget for synchronous callers. The actual publish is
    async, so we schedule it on the running event loop or silently skip if
    no loop is running.

    Args:
        event_type: One of the SUBSCRIPTION_TYPES or internal bus names.
        data: Event payload dict.
    """
    internal_type = _EVENT_MAP.get(event_type, event_type)

    try:
        from warlock.api.websocket import get_event_bus

        bus = get_event_bus()
        loop = asyncio.get_running_loop()
        loop.create_task(bus.publish(internal_type, data))
    except RuntimeError:
        # No running event loop -- skip (common in CLI / sync contexts)
        log.debug("No event loop -- skipping publish for %s", internal_type)
    except Exception as exc:
        log.debug("Failed to publish compliance event: %s", exc)
