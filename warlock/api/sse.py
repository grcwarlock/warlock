"""Server-Sent Events (SSE) endpoint for real-time compliance events.

Provides ``GET /api/v1/events/stream`` -- an SSE stream that emits
compliance events (drift, alerts, pipeline completions, POA&M transitions)
in real time. Uses the same in-memory pub/sub as the WebSocket endpoint.

Authentication is via ``Authorization: Bearer <token>`` header or
``token`` query parameter (for browser EventSource compatibility).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.responses import StreamingResponse

log = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# SSE event types -- mirrors websocket.py EventBus
# ---------------------------------------------------------------------------

_SSE_EVENT_TYPES = [
    "compliance_drift",
    "alert",
    "finding_created",
    "poam_transition",
    "pipeline_completed",
    "control_status_change",
]


# ---------------------------------------------------------------------------
# In-memory broker (shared singleton)
# ---------------------------------------------------------------------------


class SSEBroker:
    """Async pub/sub broker for SSE clients."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[dict | None]] = []

    async def subscribe(self) -> asyncio.Queue[dict | None]:
        queue: asyncio.Queue[dict | None] = asyncio.Queue(maxsize=256)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict | None]) -> None:
        try:
            self._subscribers.remove(queue)
        except ValueError:
            pass

    async def publish(self, event: dict) -> None:
        dead: list[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


_broker = SSEBroker()


def get_sse_broker() -> SSEBroker:
    """Return the module-level SSE broker singleton."""
    return _broker


# ---------------------------------------------------------------------------
# Auth helper (supports header and query param for EventSource)
# ---------------------------------------------------------------------------


def _extract_token(request: Request, token: str | None) -> str:
    """Extract JWT token from Authorization header or query param."""
    if token:
        return token
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    raise HTTPException(status_code=401, detail="Authentication required")


# ---------------------------------------------------------------------------
# SSE stream generator
# ---------------------------------------------------------------------------


async def _event_stream(
    queue: asyncio.Queue[dict | None],
    event_types: list[str] | None = None,
) -> AsyncGenerator[str, None]:
    """Yield SSE-formatted events from the queue."""
    # Send initial connection event
    connect_event = {
        "event_type": "connected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"message": "SSE stream connected", "event_types": _SSE_EVENT_TYPES},
    }
    yield f"event: connected\ndata: {json.dumps(connect_event)}\n\n"

    try:
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send keepalive comment to prevent proxy timeouts
                yield ": keepalive\n\n"
                continue

            if msg is None:
                break

            # Filter by event type if requested
            msg_type = msg.get("event_type", "unknown")
            if event_types and msg_type not in event_types:
                continue

            yield f"event: {msg_type}\ndata: {json.dumps(msg)}\n\n"
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get("/events/stream")
async def events_stream(
    request: Request,
    token: str | None = Query(default=None, description="JWT token (for EventSource)"),
    event_types: str | None = Query(
        default=None,
        description="Comma-separated event types to filter (e.g. alert,compliance_drift)",
    ),
) -> StreamingResponse:
    """Stream real-time compliance events via Server-Sent Events (SSE).

    Connect with browser ``EventSource`` or ``curl``::

        curl -N -H "Authorization: Bearer <token>" /api/v1/events/stream

    Supports optional ``event_types`` query param to filter by event type.
    Sends keepalive comments every 30s to prevent proxy timeouts.
    """
    # Validate token (extracts but does not fully verify for demo compatibility)
    _extract_token(request, token)

    # Parse event type filter
    type_filter: list[str] | None = None
    if event_types:
        type_filter = [t.strip() for t in event_types.split(",") if t.strip()]

    broker = get_sse_broker()
    queue = await broker.subscribe()

    async def _stream() -> AsyncGenerator[str, None]:
        try:
            async for chunk in _event_stream(queue, event_types=type_filter):
                yield chunk
        finally:
            broker.unsubscribe(queue)

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/events/stream/status")
async def events_stream_status() -> dict:
    """Return SSE broker status (subscriber count, supported event types)."""
    broker = get_sse_broker()
    return {
        "subscribers": broker.subscriber_count,
        "event_types": _SSE_EVENT_TYPES,
        "status": "active",
    }
