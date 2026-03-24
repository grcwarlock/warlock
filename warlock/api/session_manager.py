"""Session tracking and enforcement for Warlock GRC.

Tracks active user sessions, enforces concurrent session limits,
and handles session timeout/expiration. Uses an in-memory store
by default with optional database persistence.

SAC-2: Session management.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class SessionInfo:
    """Metadata for a single active user session."""

    user_id: str
    token_jti: str  # JWT token ID (jti claim) or hash of token
    created_at: datetime
    last_active: datetime
    ip_address: str
    user_agent: str = ""

    def is_expired(self, timeout_minutes: int) -> bool:
        """Check if this session has exceeded the inactivity timeout."""
        if timeout_minutes <= 0:
            return False
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)
        return self.last_active < cutoff


class SessionManager:
    """In-memory session tracker with concurrent session enforcement.

    Thread-safe via a reentrant lock. All public methods acquire the lock
    before accessing the session store.

    Parameters:
        timeout_minutes: Inactivity timeout in minutes (0 = no timeout).
        max_concurrent: Maximum concurrent sessions per user (0 = unlimited).
    """

    def __init__(
        self,
        timeout_minutes: int | None = None,
        max_concurrent: int | None = None,
    ) -> None:
        from warlock.config import get_settings

        settings = get_settings()
        self.timeout_minutes = (
            timeout_minutes if timeout_minutes is not None else settings.session_timeout_minutes
        )
        self.max_concurrent = (
            max_concurrent if max_concurrent is not None else settings.max_concurrent_sessions
        )
        # user_id -> {token_jti: SessionInfo}
        self._sessions: dict[str, dict[str, SessionInfo]] = {}
        self._lock = threading.RLock()

    def register_session(
        self,
        user_id: str,
        token_jti: str,
        ip_address: str,
        user_agent: str = "",
        user_max_sessions: int | None = None,
    ) -> bool:
        """Register a new session for a user.

        Returns True if the session was accepted, False if the concurrent
        session limit has been reached. Automatically cleans up expired
        sessions for the user before checking the limit.

        Args:
            user_id: The user's ID.
            token_jti: Unique identifier for the session token (JWT jti claim).
            ip_address: Client IP address.
            user_agent: Client User-Agent string.
            user_max_sessions: Per-user override for max concurrent sessions
                               (from User.max_concurrent_sessions column).
        """
        with self._lock:
            # Clean expired sessions for this user first
            self._cleanup_user_sessions(user_id)

            user_sessions = self._sessions.get(user_id, {})
            max_allowed = (
                user_max_sessions if user_max_sessions is not None else self.max_concurrent
            )

            if max_allowed > 0 and len(user_sessions) >= max_allowed:
                log.warning(
                    "Session limit reached for user %s: %d active sessions (max=%d)",
                    user_id,
                    len(user_sessions),
                    max_allowed,
                )
                return False

            now = datetime.now(timezone.utc)
            session = SessionInfo(
                user_id=user_id,
                token_jti=token_jti,
                created_at=now,
                last_active=now,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            if user_id not in self._sessions:
                self._sessions[user_id] = {}
            self._sessions[user_id][token_jti] = session

            log.info(
                "Session registered for user %s (jti=%s, ip=%s, active=%d)",
                user_id,
                token_jti[:8],
                ip_address,
                len(self._sessions[user_id]),
            )
            return True

    def validate_session(self, user_id: str, token_jti: str) -> bool:
        """Check if a session is still valid (exists and not expired).

        Also updates the last_active timestamp on valid sessions.
        Returns False if the session does not exist or has expired.
        """
        with self._lock:
            user_sessions = self._sessions.get(user_id, {})
            session = user_sessions.get(token_jti)

            if not session:
                return False

            if session.is_expired(self.timeout_minutes):
                # Remove expired session
                del user_sessions[token_jti]
                if not user_sessions:
                    del self._sessions[user_id]
                log.info(
                    "Session expired for user %s (jti=%s, inactive for >%d min)",
                    user_id,
                    token_jti[:8],
                    self.timeout_minutes,
                )
                return False

            # Touch the session — update last_active
            session.last_active = datetime.now(timezone.utc)
            return True

    def invalidate_session(self, user_id: str, token_jti: str) -> bool:
        """Remove a specific session (e.g., on logout).

        Returns True if the session was found and removed.
        """
        with self._lock:
            user_sessions = self._sessions.get(user_id, {})
            if token_jti in user_sessions:
                del user_sessions[token_jti]
                if not user_sessions:
                    del self._sessions[user_id]
                log.info("Session invalidated for user %s (jti=%s)", user_id, token_jti[:8])
                return True
            return False

    def invalidate_all_sessions(self, user_id: str) -> int:
        """Remove all sessions for a user (e.g., on password change or account deactivation).

        Returns the number of sessions that were invalidated.
        """
        with self._lock:
            user_sessions = self._sessions.pop(user_id, {})
            count = len(user_sessions)
            if count > 0:
                log.info("All %d sessions invalidated for user %s", count, user_id)
            return count

    def get_user_sessions(self, user_id: str) -> list[dict[str, Any]]:
        """Get all active sessions for a user.

        Returns a list of session info dicts (safe for API response).
        Automatically cleans up expired sessions first.
        """
        with self._lock:
            self._cleanup_user_sessions(user_id)
            user_sessions = self._sessions.get(user_id, {})
            return [
                {
                    "token_jti": s.token_jti[:8] + "...",  # Truncate for security
                    "created_at": s.created_at.isoformat(),
                    "last_active": s.last_active.isoformat(),
                    "ip_address": s.ip_address,
                    "user_agent": s.user_agent[:100] if s.user_agent else "",
                }
                for s in user_sessions.values()
            ]

    def active_session_count(self, user_id: str) -> int:
        """Return the number of active (non-expired) sessions for a user."""
        with self._lock:
            self._cleanup_user_sessions(user_id)
            return len(self._sessions.get(user_id, {}))

    def cleanup_expired(self) -> int:
        """Remove all expired sessions across all users.

        Returns the total number of sessions removed. Should be called
        periodically (e.g., via a background task or scheduler).
        """
        with self._lock:
            total_removed = 0
            empty_users = []

            for user_id, sessions in self._sessions.items():
                expired_jtis = [
                    jti for jti, s in sessions.items() if s.is_expired(self.timeout_minutes)
                ]
                for jti in expired_jtis:
                    del sessions[jti]
                    total_removed += 1

                if not sessions:
                    empty_users.append(user_id)

            for user_id in empty_users:
                del self._sessions[user_id]

            if total_removed > 0:
                log.info(
                    "Session cleanup: removed %d expired sessions across %d users",
                    total_removed,
                    len(empty_users),
                )
            return total_removed

    def stats(self) -> dict[str, Any]:
        """Return session manager statistics."""
        with self._lock:
            total_sessions = sum(len(s) for s in self._sessions.values())
            total_users = len(self._sessions)
            return {
                "total_active_sessions": total_sessions,
                "total_users_with_sessions": total_users,
                "timeout_minutes": self.timeout_minutes,
                "max_concurrent_per_user": self.max_concurrent,
            }

    def _cleanup_user_sessions(self, user_id: str) -> None:
        """Remove expired sessions for a specific user. Must be called with lock held."""
        sessions = self._sessions.get(user_id, {})
        expired_jtis = [jti for jti, s in sessions.items() if s.is_expired(self.timeout_minutes)]
        for jti in expired_jtis:
            del sessions[jti]
        if not sessions and user_id in self._sessions:
            del self._sessions[user_id]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Get the global SessionManager instance."""
    global _manager
    if _manager is None:
        _manager = SessionManager()
    return _manager
