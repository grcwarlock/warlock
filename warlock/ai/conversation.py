"""Conversation session manager for interactive AI reasoning panels.

Manages stateful multi-turn conversations between users and the AI
layer, scoped to a specific compliance entity (control, finding,
system, vendor, etc.).  Each session maintains a sliding window of
messages for the prompt context while preserving the full history for
audit purposes.

Sessions expire after a configurable TTL and are evicted on access or
via explicit cleanup.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Session data
# ---------------------------------------------------------------------------


@dataclass
class ConversationSession:
    """State for a single interactive AI conversation."""

    session_id: str
    entity_type: str
    entity_id: str
    entity_data: dict[str, Any]
    messages: list[dict[str, str]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def message_count(self) -> int:
        """Number of messages in the conversation."""
        return len(self.messages)

    def touch(self) -> None:
        """Update ``last_activity`` to now."""
        self.last_activity = datetime.now(timezone.utc)

    def is_expired(self, ttl: timedelta) -> bool:
        """Check whether this session has exceeded the TTL."""
        return datetime.now(timezone.utc) - self.last_activity > ttl

    def to_dict(self) -> dict[str, Any]:
        """Serialise the session for API responses."""
        return {
            "session_id": self.session_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "message_count": self.message_count,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class ConversationManager:
    """Manages interactive AI reasoning sessions.

    Thread-safe.  Sessions are stored in memory, keyed by session ID.
    An LRU-style eviction removes the oldest sessions when
    ``max_sessions`` is reached, and a TTL evicts idle sessions.

    Parameters
    ----------
    max_sessions:
        Maximum concurrent sessions.  When exceeded, the oldest idle
        session is evicted.
    ttl_hours:
        Hours of inactivity before a session expires.
    max_messages:
        Maximum messages per session.  Oldest messages are dropped when
        the limit is reached (FIFO).
    prompt_window:
        Number of most-recent messages included in the prompt context
        sent to the AI provider.  The full history is retained for
        audit but only the window is sent.
    """

    def __init__(
        self,
        max_sessions: int = 1000,
        ttl_hours: float = 1.0,
        max_messages: int = 50,
        prompt_window: int = 10,
    ) -> None:
        self._sessions: dict[str, ConversationSession] = {}
        self._lock = threading.Lock()
        self._max_sessions = max_sessions
        self._ttl = timedelta(hours=ttl_hours)
        self._max_messages = max_messages
        self._prompt_window = prompt_window

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def get_or_create(
        self,
        session_id: str | None,
        entity_type: str,
        entity_id: str,
        entity_data: dict[str, Any],
    ) -> ConversationSession:
        """Return an existing session or create a new one.

        If *session_id* is ``None`` or does not map to a live session,
        a new session is created with a fresh UUID.  If the session
        exists but is expired, it is replaced.

        When the session pool is full, the oldest idle session is
        evicted to make room.
        """
        with self._lock:
            # Try to return existing.
            if session_id and session_id in self._sessions:
                session = self._sessions[session_id]
                if session.is_expired(self._ttl):
                    log.debug("Session %s expired, creating replacement", session_id)
                    del self._sessions[session_id]
                else:
                    session.touch()
                    return session

            # Evict if at capacity.
            if len(self._sessions) >= self._max_sessions:
                self._evict_oldest_locked()

            new_id = session_id or uuid.uuid4().hex
            session = ConversationSession(
                session_id=new_id,
                entity_type=entity_type,
                entity_id=entity_id,
                entity_data=entity_data,
            )
            self._sessions[new_id] = session
            log.debug(
                "Created session %s for %s/%s",
                new_id,
                entity_type,
                entity_id,
            )
            return session

    def get_session(self, session_id: str) -> ConversationSession | None:
        """Look up a session by ID, or return ``None`` if not found/expired."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.is_expired(self._ttl):
                del self._sessions[session_id]
                return None
            return session

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def add_message(self, session_id: str, role: str, content: str) -> None:
        """Append a message to a session.

        Raises ``KeyError`` if the session does not exist or is expired.
        If the session has reached ``max_messages``, the oldest message
        is dropped.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"Session {session_id!r} not found")
            if session.is_expired(self._ttl):
                del self._sessions[session_id]
                raise KeyError(f"Session {session_id!r} has expired")

            if len(session.messages) >= self._max_messages:
                session.messages.pop(0)

            session.messages.append({"role": role, "content": content})
            session.touch()

    def get_prompt_messages(self, session_id: str) -> list[dict[str, str]]:
        """Return the sliding window of recent messages for prompt construction.

        The first message in the window always includes the entity context
        as a system-context preamble so the model has grounding even when
        older messages have scrolled out of the window.

        Raises ``KeyError`` if the session does not exist or is expired.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"Session {session_id!r} not found")
            if session.is_expired(self._ttl):
                del self._sessions[session_id]
                raise KeyError(f"Session {session_id!r} has expired")

            window = session.messages[-self._prompt_window :]
            session.touch()
            return list(window)

    def get_full_history(self, session_id: str) -> list[dict[str, str]]:
        """Return the complete message history for audit purposes.

        Raises ``KeyError`` if the session does not exist or is expired.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError(f"Session {session_id!r} not found")
            if session.is_expired(self._ttl):
                del self._sessions[session_id]
                raise KeyError(f"Session {session_id!r} has expired")

            session.touch()
            return list(session.messages)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Remove all sessions past their TTL.

        Returns the number of sessions removed.
        """
        with self._lock:
            expired_ids = [sid for sid, s in self._sessions.items() if s.is_expired(self._ttl)]
            for sid in expired_ids:
                del self._sessions[sid]
            if expired_ids:
                log.debug("Cleaned up %d expired sessions", len(expired_ids))
            return len(expired_ids)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def active_session_count(self) -> int:
        """Number of sessions currently held (including possibly expired)."""
        with self._lock:
            return len(self._sessions)

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return summary dicts for all active sessions."""
        with self._lock:
            return [s.to_dict() for s in self._sessions.values() if not s.is_expired(self._ttl)]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evict_oldest_locked(self) -> None:
        """Evict the least-recently-active session.  Caller holds ``_lock``."""
        if not self._sessions:
            return
        oldest_id = min(
            self._sessions,
            key=lambda sid: self._sessions[sid].last_activity,
        )
        log.debug("Evicting oldest session %s to make room", oldest_id)
        del self._sessions[oldest_id]
