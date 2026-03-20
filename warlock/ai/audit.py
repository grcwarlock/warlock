"""AI call audit logging.

Every AI invocation -- whether it reaches a model or falls back to a
deterministic path -- gets an ``AIAuditEntry`` recorded.  The
``AIAuditLog`` holds entries in memory with optional database
persistence via a caller-supplied flush callback.

This is the compliance-critical audit trail for AI usage: prompt hashes
for reproducibility, token counts for cost attribution, latency for SLA
tracking, and confidence scores for quality monitoring.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Audit entry
# ---------------------------------------------------------------------------


@dataclass
class AIAuditEntry:
    """Single audit record for one AI invocation."""

    id: str
    timestamp: datetime
    task: str
    provider: str
    model: str
    prompt_hash: str
    latency_ms: int
    tokens_input: int | None
    tokens_output: int | None
    confidence: float
    ai_used: bool
    fallback_reason: str
    user_id: str | None = None
    entity_type: str | None = None
    entity_id: str | None = None
    session_id: str | None = None

    @staticmethod
    def create(
        *,
        task: str,
        provider: str,
        model: str,
        prompt_hash: str,
        latency_ms: int,
        tokens_input: int | None = None,
        tokens_output: int | None = None,
        confidence: float = 0.0,
        ai_used: bool = True,
        fallback_reason: str = "",
        user_id: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        session_id: str | None = None,
    ) -> AIAuditEntry:
        """Factory that auto-generates ``id`` and ``timestamp``."""
        return AIAuditEntry(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc),
            task=task,
            provider=provider,
            model=model,
            prompt_hash=prompt_hash,
            latency_ms=latency_ms,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            confidence=confidence,
            ai_used=ai_used,
            fallback_reason=fallback_reason,
            user_id=user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            session_id=session_id,
        )


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

# Type alias for optional persistence callbacks.
FlushCallback = Callable[[list[AIAuditEntry]], None]


class AIAuditLog:
    """In-memory audit log with optional database persistence.

    Thread-safe.  Entries are stored in a bounded deque so memory usage
    is predictable even under sustained load.  An optional ``flush_cb``
    is invoked when the buffer reaches ``flush_threshold`` entries,
    allowing the caller to persist batches to a database.

    Parameters
    ----------
    max_entries:
        Maximum entries retained in memory.  Oldest entries are evicted
        when the limit is reached.
    flush_cb:
        Optional callback invoked with a batch of entries for database
        persistence.
    flush_threshold:
        Number of new entries that triggers an automatic flush.  Set to
        0 to disable auto-flush (caller must invoke ``flush`` manually).
    """

    def __init__(
        self,
        max_entries: int = 10_000,
        flush_cb: FlushCallback | None = None,
        flush_threshold: int = 100,
    ) -> None:
        self._entries: deque[AIAuditEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._flush_cb = flush_cb
        self._flush_threshold = flush_threshold
        self._unflushed: list[AIAuditEntry] = []
        # Counters for stats (not bounded by deque eviction).
        self._total_recorded: int = 0
        self._total_errors: int = 0

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, entry: AIAuditEntry) -> None:
        """Append an audit entry.

        If a ``flush_cb`` was provided and the unflushed buffer reaches
        ``flush_threshold``, the callback is invoked in the calling
        thread (not deferred).
        """
        with self._lock:
            self._entries.append(entry)
            self._total_recorded += 1
            if not entry.ai_used and entry.fallback_reason:
                self._total_errors += 1
            if self._flush_cb is not None:
                self._unflushed.append(entry)
                if (
                    self._flush_threshold > 0
                    and len(self._unflushed) >= self._flush_threshold
                ):
                    self._flush_locked()

    def flush(self) -> int:
        """Manually flush unflushed entries to the persistence callback.

        Returns the number of entries flushed.
        """
        with self._lock:
            return self._flush_locked()

    def _flush_locked(self) -> int:
        """Flush while already holding ``_lock``."""
        if not self._unflushed or self._flush_cb is None:
            return 0
        batch = list(self._unflushed)
        self._unflushed.clear()
        try:
            self._flush_cb(batch)
        except Exception:
            log.exception("AI audit flush callback failed for %d entries", len(batch))
            # Re-queue so entries are not silently lost.
            self._unflushed.extend(batch)
            return 0
        return len(batch)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_recent(self, limit: int = 100) -> list[AIAuditEntry]:
        """Return the most recent *limit* entries, newest first."""
        with self._lock:
            items = list(self._entries)
        items.reverse()
        return items[:limit]

    def get_by_session(self, session_id: str) -> list[AIAuditEntry]:
        """Return all entries for a conversation session, oldest first."""
        with self._lock:
            return [e for e in self._entries if e.session_id == session_id]

    def get_by_entity(
        self, entity_type: str, entity_id: str
    ) -> list[AIAuditEntry]:
        """Return all entries for a specific entity, oldest first."""
        with self._lock:
            return [
                e
                for e in self._entries
                if e.entity_type == entity_type and e.entity_id == entity_id
            ]

    # ------------------------------------------------------------------
    # Aggregated stats
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return summary statistics for monitoring dashboards.

        Keys:
        - ``total_recorded``: lifetime count of entries recorded.
        - ``in_memory``: entries currently held in the deque.
        - ``errors``: lifetime count of fallback/error entries.
        - ``avg_confidence``: mean confidence across in-memory entries.
        - ``avg_latency_ms``: mean latency across in-memory entries.
        - ``ai_used_pct``: percentage of calls that used the AI model.
        - ``by_task``: per-task call counts.
        - ``by_provider``: per-provider call counts.
        """
        with self._lock:
            entries = list(self._entries)

        total = len(entries)
        if total == 0:
            return {
                "total_recorded": self._total_recorded,
                "in_memory": 0,
                "errors": self._total_errors,
                "avg_confidence": 0.0,
                "avg_latency_ms": 0.0,
                "ai_used_pct": 0.0,
                "by_task": {},
                "by_provider": {},
            }

        confidences = [e.confidence for e in entries]
        latencies = [e.latency_ms for e in entries]
        ai_used_count = sum(1 for e in entries if e.ai_used)

        by_task: dict[str, int] = {}
        by_provider: dict[str, int] = {}
        for e in entries:
            by_task[e.task] = by_task.get(e.task, 0) + 1
            by_provider[e.provider] = by_provider.get(e.provider, 0) + 1

        return {
            "total_recorded": self._total_recorded,
            "in_memory": total,
            "errors": self._total_errors,
            "avg_confidence": round(sum(confidences) / total, 4),
            "avg_latency_ms": round(sum(latencies) / total, 1),
            "ai_used_pct": round(ai_used_count / total * 100, 1),
            "by_task": by_task,
            "by_provider": by_provider,
        }

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def entry_to_dict(entry: AIAuditEntry) -> dict:
        """Convert an entry to a JSON-serialisable dict."""
        d = asdict(entry)
        d["timestamp"] = entry.timestamp.isoformat()
        return d


# Re-export for backwards compatibility -- canonical implementation lives
# in ``warlock.ai.sanitize``.
from warlock.ai.sanitize import hash_prompt  # noqa: E402, F401
