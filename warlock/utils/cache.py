"""Shared cache abstraction for multi-worker compatibility.

Uses in-memory dict by default. When WLK_CACHE_URL is set (e.g. redis://localhost:6379),
uses Redis for cross-worker state sharing.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any

log = logging.getLogger(__name__)


class CacheBackend:
    """Abstract cache interface."""

    def get(self, key: str) -> Any | None:
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: int = 300) -> None:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def increment(self, key: str, ttl: int = 60) -> int:
        raise NotImplementedError


class MemoryCache(CacheBackend):
    """Thread-safe in-memory cache with TTL eviction."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}  # key -> (value, expires_at)
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl: int = 300) -> None:
        with self._lock:
            self._store[key] = (value, time.time() + ttl)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def increment(self, key: str, ttl: int = 60) -> int:
        with self._lock:
            entry = self._store.get(key)
            if entry is None or time.time() > entry[1]:
                self._store[key] = (1, time.time() + ttl)
                return 1
            count = entry[0] + 1
            self._store[key] = (count, entry[1])
            return count


class RedisCache(CacheBackend):
    """Redis-backed cache for multi-worker deployments."""

    def __init__(self, url: str) -> None:
        self._fallback: MemoryCache | None = None
        self._redis: Any = None
        try:
            import redis

            self._redis = redis.from_url(url, decode_responses=True)
            self._redis.ping()
            log.info("Redis cache connected: %s", url)
        except Exception:
            log.warning(
                "Redis connection failed (%s) — falling back to memory cache",
                url,
            )
            self._fallback = MemoryCache()
            self._redis = None

    def get(self, key: str) -> Any | None:
        if not self._redis:
            return self._fallback.get(key)  # type: ignore[union-attr]
        raw = self._redis.get(f"warlock:{key}")
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw

    def set(self, key: str, value: Any, ttl: int = 300) -> None:
        if not self._redis:
            return self._fallback.set(key, value, ttl)  # type: ignore[union-attr]
        self._redis.setex(f"warlock:{key}", ttl, json.dumps(value, default=str))

    def delete(self, key: str) -> None:
        if not self._redis:
            return self._fallback.delete(key)  # type: ignore[union-attr]
        self._redis.delete(f"warlock:{key}")

    def increment(self, key: str, ttl: int = 60) -> int:
        if not self._redis:
            return self._fallback.increment(key, ttl)  # type: ignore[union-attr]
        pipe = self._redis.pipeline()
        pipe.incr(f"warlock:{key}")
        pipe.expire(f"warlock:{key}", ttl)
        result = pipe.execute()
        return result[0]


_cache: CacheBackend | None = None


def get_cache() -> CacheBackend:
    """Return the shared cache singleton. Redis if WLK_CACHE_URL is set, else memory."""
    global _cache
    if _cache is None:
        import os

        cache_url = os.environ.get("WLK_CACHE_URL", "").strip()
        if cache_url:
            _cache = RedisCache(cache_url)
        else:
            _cache = MemoryCache()
    return _cache
