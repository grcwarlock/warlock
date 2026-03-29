"""WebSocket endpoint for real-time compliance event streaming.

Provides `/api/v1/ws/events` — authenticated via token query parameter.
Uses simple in-memory pub/sub for event distribution.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

log = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# In-memory pub/sub
# ---------------------------------------------------------------------------

_EVENT_TYPES = [
    "compliance_drift",
    "alert",
    "finding_created",
    "poam_transition",
    "pipeline_completed",
    "control_status_change",
]


class EventBus:
    """Simple in-memory pub/sub for WebSocket event distribution."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        message = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": payload,
        }
        dead: list[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)


event_bus = EventBus()


def get_event_bus() -> EventBus:
    """Return the singleton event bus."""
    return event_bus


# ---------------------------------------------------------------------------
# Authentication helper
# ---------------------------------------------------------------------------


def _verify_ws_token(token: str) -> dict | None:
    """Verify a WebSocket auth token. Returns user claims or None."""
    try:
        from warlock.api.auth import decode_token

        return decode_token(token)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/events")
async def ws_events(
    websocket: WebSocket,
    token: str = Query(default=""),
) -> None:
    """Real-time compliance event stream.

    Connect with: ws://host/api/v1/ws/events?token=<jwt>

    Events: compliance_drift, alert, finding_created, poam_transition,
    pipeline_completed, control_status_change.
    """
    # Authenticate
    claims = _verify_ws_token(token)
    if not claims:
        await websocket.close(code=4001, reason="Invalid or missing token")
        return

    await websocket.accept()
    log.info("WebSocket client connected: %s", claims.get("sub", "unknown"))

    queue = event_bus.subscribe()
    try:
        while True:
            message = await queue.get()
            await websocket.send_text(json.dumps(message, default=str))
    except WebSocketDisconnect:
        log.info("WebSocket client disconnected")
    except Exception:
        log.exception("WebSocket error")
    finally:
        event_bus.unsubscribe(queue)
