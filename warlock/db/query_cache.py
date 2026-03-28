"""Redis-backed query cache for expensive dashboard queries.

ARCH-021: Caches expensive aggregation queries (compliance posture, drift,
risk summaries) with tag-based invalidation. Falls back to an in-memory
dict with TTL expiry when no Redis URL is configured.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from warlock.config import get_settings

try:
    import redis

    _HAS_REDIS = True
except ImportError:
    _HAS_REDIS = False

log = logging.getLogger(__name__)


class QueryCache:
    """Two-tier cache: Redis when available, in-memory dict otherwise."""

    def __init__(self, cache_url: str = "") -> None:
        self._url = cache_url or get_settings().cache_url
        self._redis: Any | None = None
        self._memory: dict[str, dict[str, Any]] = {}
        # tag -> set of keys, for invalidate_tag
        self._tags: dict[str, set[str]] = {}

        if self._url and _HAS_REDIS:
            try:
                self._redis = redis.from_url(self._url, decode_responses=True)
                self._redis.ping()
                log.info("QueryCache connected to Redis: %s", self._url)
            except Exception as exc:
                log.warning("QueryCache Redis unavailable, falling back to in-memory: %s", exc)
                self._redis = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str) -> dict | None:
        """Return cached value or None if missing/expired."""
        if self._redis is not None:
            try:
                raw = self._redis.get(f"qc:{key}")
                if raw is not None:
                    return json.loads(raw)
            except Exception:
                log.debug("QueryCache Redis get failed for key=%s", key, exc_info=True)
            return None

        # In-memory path
        entry = self._memory.get(key)
        if entry is None:
            return None
        if entry["expires_at"] < time.time():
            del self._memory[key]
            return None
        return entry["value"]

    def set(self, key: str, value: dict, ttl: int = 300, tags: list[str] | None = None) -> None:
        """Store a value with TTL (seconds). Optionally tag for group invalidation."""
        if self._redis is not None:
            try:
                self._redis.setex(f"qc:{key}", ttl, json.dumps(value, default=str))
                for tag in tags or []:
                    self._redis.sadd(f"qc:tag:{tag}", f"qc:{key}")
            except Exception:
                log.debug("QueryCache Redis set failed for key=%s", key, exc_info=True)
            return

        # In-memory path
        self._memory[key] = {
            "value": value,
            "expires_at": time.time() + ttl,
        }
        for tag in tags or []:
            self._tags.setdefault(tag, set()).add(key)

    def invalidate_tag(self, tag: str) -> None:
        """Invalidate all cache entries with this tag (e.g. 'dashboard')."""
        if self._redis is not None:
            try:
                members = self._redis.smembers(f"qc:tag:{tag}")
                if members:
                    self._redis.delete(*members)
                self._redis.delete(f"qc:tag:{tag}")
            except Exception:
                log.debug("QueryCache Redis invalidate_tag failed for tag=%s", tag, exc_info=True)
            return

        # In-memory path
        keys = self._tags.pop(tag, set())
        for key in keys:
            self._memory.pop(key, None)

    def invalidate_all(self) -> None:
        """Flush the entire cache."""
        if self._redis is not None:
            try:
                # Delete all keys with our prefix
                cursor = 0
                while True:
                    cursor, keys = self._redis.scan(cursor, match="qc:*", count=100)
                    if keys:
                        self._redis.delete(*keys)
                    if cursor == 0:
                        break
            except Exception:
                log.debug("QueryCache Redis invalidate_all failed", exc_info=True)
            return

        # In-memory path
        self._memory.clear()
        self._tags.clear()


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_cache: QueryCache | None = None


def get_query_cache() -> QueryCache:
    """Return the global QueryCache singleton."""
    global _cache
    if _cache is None:
        _cache = QueryCache()
    return _cache
