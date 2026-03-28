"""Single-process scheduler leader election.

ARCH-019: Ensures only one scheduler instance runs pipeline collection
across multiple workers. Supports file-based (dev/SQLite) and Redis-based
(production) backends.

Config: WLK_LEADER_ELECTION_BACKEND (file/redis), defaults to "file".
Redis backend uses the shared WLK_CACHE_URL.
"""

from __future__ import annotations

import logging
import os
import time

from warlock.config import get_settings

try:
    import redis

    _HAS_REDIS = True
except ImportError:
    _HAS_REDIS = False

log = logging.getLogger(__name__)


class LeaderElection:
    """Ensure only one scheduler instance runs across multiple workers."""

    def __init__(self, backend: str = "") -> None:
        settings = get_settings()
        self._backend = backend or getattr(settings, "leader_election_backend", "file")
        self._pid = os.getpid()
        self._lock_files: dict[str, object] = {}
        self._redis_client = None

        if self._backend == "redis":
            cache_url = settings.cache_url
            if cache_url and _HAS_REDIS:
                try:
                    self._redis_client = redis.from_url(cache_url, decode_responses=True)
                    self._redis_client.ping()
                    log.info("LeaderElection connected to Redis: %s", cache_url)
                except Exception as exc:
                    log.warning("LeaderElection Redis unavailable, falling back to file: %s", exc)
                    self._backend = "file"
            else:
                log.warning("LeaderElection: Redis requested but unavailable, using file backend")
                self._backend = "file"

    def try_acquire(self, name: str = "scheduler", ttl: int = 60) -> bool:
        """Attempt to become the leader. Returns True if acquired."""
        if self._backend == "redis" and self._redis_client is not None:
            return self._try_acquire_redis(name, ttl)
        return self._try_acquire_file(name)

    def release(self, name: str = "scheduler") -> None:
        """Release leadership."""
        if self._backend == "redis" and self._redis_client is not None:
            self._release_redis(name)
        else:
            self._release_file(name)

    def is_leader(self, name: str = "scheduler") -> bool:
        """Check if this process is the current leader."""
        if self._backend == "redis" and self._redis_client is not None:
            return self._is_leader_redis(name)
        return self._is_leader_file(name)

    # ------------------------------------------------------------------
    # File-based backend (lockfile with PID)
    # ------------------------------------------------------------------

    def _lock_path(self, name: str) -> str:
        return os.path.join(os.environ.get("TMPDIR", "/tmp"), f"warlock_leader_{name}.lock")

    def _try_acquire_file(self, name: str) -> bool:
        path = self._lock_path(name)

        # Check for stale lock
        if os.path.exists(path):
            try:
                with open(path) as f:
                    holder_pid = int(f.read().strip())
                if holder_pid == self._pid:
                    return True  # We already hold it
                os.kill(holder_pid, 0)  # Check if alive
                return False  # Another live process holds it
            except (ValueError, OSError):
                # Stale lock — holder is dead
                log.warning("Reclaiming stale leader lock for %s", name)
                try:
                    os.unlink(path)
                except OSError:
                    pass

        # Acquire
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(self._pid).encode())
            os.close(fd)
            log.info("Acquired leader lock for %s (pid=%d)", name, self._pid)
            return True
        except FileExistsError:
            return False

    def _release_file(self, name: str) -> None:
        path = self._lock_path(name)
        try:
            with open(path) as f:
                holder_pid = int(f.read().strip())
            if holder_pid == self._pid:
                os.unlink(path)
                log.info("Released leader lock for %s", name)
        except (FileNotFoundError, ValueError, OSError):
            pass

    def _is_leader_file(self, name: str) -> bool:
        path = self._lock_path(name)
        try:
            with open(path) as f:
                holder_pid = int(f.read().strip())
            return holder_pid == self._pid
        except (FileNotFoundError, ValueError, OSError):
            return False

    # ------------------------------------------------------------------
    # Redis-based backend (SETNX with TTL)
    # ------------------------------------------------------------------

    def _redis_key(self, name: str) -> str:
        return f"warlock:leader:{name}"

    def _try_acquire_redis(self, name: str, ttl: int) -> bool:
        key = self._redis_key(name)
        value = f"{self._pid}:{time.time()}"
        try:
            acquired = self._redis_client.set(key, value, nx=True, ex=ttl)
            if acquired:
                log.info("Acquired Redis leader lock for %s", name)
                return True
            # Check if we already hold it
            current = self._redis_client.get(key)
            if current and current.startswith(f"{self._pid}:"):
                # Refresh TTL
                self._redis_client.expire(key, ttl)
                return True
            return False
        except Exception:
            log.debug("Redis leader election failed for %s", name, exc_info=True)
            return False

    def _release_redis(self, name: str) -> None:
        key = self._redis_key(name)
        try:
            current = self._redis_client.get(key)
            if current and current.startswith(f"{self._pid}:"):
                self._redis_client.delete(key)
                log.info("Released Redis leader lock for %s", name)
        except Exception:
            log.debug("Redis leader release failed for %s", name, exc_info=True)

    def _is_leader_redis(self, name: str) -> bool:
        key = self._redis_key(name)
        try:
            current = self._redis_client.get(key)
            return bool(current and current.startswith(f"{self._pid}:"))
        except Exception:
            return False
