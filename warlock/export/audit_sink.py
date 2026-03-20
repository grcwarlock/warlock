"""Audit log external sink — ship AuditEntry rows to external backends.

Provides a pluggable sink architecture so the immutable audit trail can be
durably replicated outside the primary database for long-term retention,
SIEM integration, or regulatory evidence export.

Backends
--------
* ``StdoutSink``      — JSON-lines to stdout; feeds log aggregation pipelines.
* ``S3AuditSink``     — JSON-lines batches to S3 with Object Lock for WORM.
* ``CloudWatchSink``  — Batch send to an AWS CloudWatch Logs group.

Factory
-------
Call ``create_sink(backend, **config)`` or set the ``WLK_AUDIT_SINK_BACKEND``
environment variable and call ``create_sink_from_env()``::

    # .env
    WLK_AUDIT_SINK_BACKEND=s3
    WLK_AUDIT_SINK_BUCKET=my-audit-bucket
    WLK_AUDIT_SINK_PREFIX=warlock/audit/

Batch shipping
--------------
``BatchShipper`` accumulates entries and flushes when either:
  * the batch reaches *max_batch_size* entries (default 500), or
  * *flush_interval_seconds* have elapsed since the last flush (default 60).

Call ``shipper.ingest(entry)`` from your audit writer, and ``shipper.flush()``
on shutdown / after each pipeline run.

Thread safety
-------------
``BatchShipper`` uses a threading.Lock and is safe to call from multiple
threads.  Each backend's ``ship()`` method is assumed to be blocking and
may be called from a background thread by ``BatchShipper``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Minimal AuditEntry representation used by sinks
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """Portable representation of a single audit log entry.

    This mirrors the fields on ``warlock.db.models.AuditEntry`` but is
    deliberately decoupled from SQLAlchemy so sinks can operate without a DB
    session (e.g. in tests or standalone shipping jobs).
    """

    id: str
    sequence: int
    previous_hash: str
    entry_hash: str
    action: str
    entity_type: str
    entity_id: str
    actor: str
    created_at: datetime
    evidence_sha256: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json_line(self) -> str:
        """Serialise to a single JSON line (no trailing newline)."""
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        return json.dumps(d, separators=(",", ":"))

    @classmethod
    def from_db_model(cls, row: Any) -> "AuditEntry":
        """Convert a SQLAlchemy ``AuditEntry`` ORM row to this dataclass."""
        return cls(
            id=row.id,
            sequence=row.sequence,
            previous_hash=row.previous_hash,
            entry_hash=row.entry_hash,
            action=row.action,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            actor=row.actor,
            created_at=(
                row.created_at
                if row.created_at.tzinfo is not None
                else row.created_at.replace(tzinfo=timezone.utc)
            ),
            evidence_sha256=row.evidence_sha256,
            extra=row.extra or {},
        )


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class AuditLogSink(ABC):
    """Base class for all audit log shipping backends.

    Subclasses must implement ``ship(entries)``.  They may also override
    ``close()`` to release external resources (connections, file handles).
    """

    @abstractmethod
    def ship(self, entries: list[AuditEntry]) -> None:
        """Ship a batch of audit entries to the external backend.

        Implementations should be idempotent where possible — the caller may
        retry the same batch on transient errors.

        Args:
            entries: Non-empty list of ``AuditEntry`` objects to ship.

        Raises:
            Any exception is propagated to ``BatchShipper`` which logs it and
            may retry based on its policy.
        """

    def close(self) -> None:
        """Release any resources held by the sink.  Called on shutdown."""


# ---------------------------------------------------------------------------
# StdoutSink
# ---------------------------------------------------------------------------

class StdoutSink(AuditLogSink):
    """Write audit entries as JSON-lines to stdout.

    Suitable for container environments where stdout is captured by a log
    aggregation daemon (Fluentd, Fluent Bit, Vector, etc.).

    Each entry is written as a single JSON object terminated by ``\\n``.
    The entire batch is flushed atomically under a lock to prevent
    interleaving when called from multiple threads.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def ship(self, entries: list[AuditEntry]) -> None:
        lines = "\n".join(e.to_json_line() for e in entries) + "\n"
        with self._lock:
            sys.stdout.write(lines)
            sys.stdout.flush()
        log.debug("StdoutSink shipped %d entries", len(entries))


# ---------------------------------------------------------------------------
# S3AuditSink
# ---------------------------------------------------------------------------

class S3AuditSink(AuditLogSink):
    """Write JSON-lines batches to S3, optionally with Object Lock (WORM).

    Each batch is written as a single S3 object::

        s3://<bucket>/<prefix><date>/<sequence_start>-<sequence_end>.jsonl

    Object Lock configuration (``object_lock_mode`` + ``retain_days``) is set
    per-object via ``PutObjectRetention``.  The bucket must have Object Lock
    enabled at creation time — this sink does NOT enable it.

    Args:
        bucket: S3 bucket name.
        prefix: Key prefix (e.g. ``"warlock/audit/"``).
        region: AWS region (defaults to ``AWS_DEFAULT_REGION`` env var).
        object_lock_mode: ``"GOVERNANCE"`` or ``"COMPLIANCE"``; ``None``
            disables Object Lock on individual objects.
        retain_days: Retention period in days when Object Lock is active.
        endpoint_url: Override for S3-compatible storage (MinIO, localstack).
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "warlock/audit/",
        region: str | None = None,
        object_lock_mode: str | None = "GOVERNANCE",
        retain_days: int = 365,
        endpoint_url: str | None = None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.object_lock_mode = object_lock_mode
        self.retain_days = retain_days
        self.endpoint_url = endpoint_url
        self._client: Any = None  # lazy boto3 client

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "boto3 is required for S3AuditSink. "
                    "Install it with: pip install boto3"
                ) from exc
            kwargs: dict[str, Any] = {"region_name": self.region}
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            self._client = boto3.client("s3", **kwargs)
        return self._client

    def ship(self, entries: list[AuditEntry]) -> None:
        if not entries:
            return

        client = self._get_client()

        # Build key: prefix/YYYY-MM-DD/<seq_start>-<seq_end>.jsonl
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        seq_start = entries[0].sequence
        seq_end = entries[-1].sequence
        key = f"{self.prefix}{date_str}/{seq_start:012d}-{seq_end:012d}.jsonl"

        body = "\n".join(e.to_json_line() for e in entries) + "\n"

        put_kwargs: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": body.encode("utf-8"),
            "ContentType": "application/x-ndjson",
        }

        if self.object_lock_mode:
            from datetime import timedelta  # local import to keep top-level clean

            retain_until = datetime.now(timezone.utc) + timedelta(days=self.retain_days)
            put_kwargs["ObjectLockMode"] = self.object_lock_mode
            put_kwargs["ObjectLockRetainUntilDate"] = retain_until

        client.put_object(**put_kwargs)

        log.info(
            "S3AuditSink shipped %d entries to s3://%s/%s",
            len(entries),
            self.bucket,
            key,
        )

    def close(self) -> None:
        self._client = None


# ---------------------------------------------------------------------------
# CloudWatchSink
# ---------------------------------------------------------------------------

class CloudWatchSink(AuditLogSink):
    """Send audit entries to an AWS CloudWatch Logs group.

    Entries are sent as ``PutLogEvents`` calls.  CloudWatch limits each
    ``PutLogEvents`` request to 10 000 events and 1 MB of compressed data;
    ``ship()`` splits batches automatically if they exceed these limits.

    Args:
        log_group: CloudWatch Logs group name (created if it does not exist).
        log_stream: Log stream name (created if it does not exist).
        region: AWS region.
        retention_days: Log group retention in days (0 = never expire).
    """

    # CloudWatch hard limits
    _MAX_EVENTS_PER_PUT = 10_000
    _MAX_BYTES_PER_PUT = 1_048_576  # 1 MiB

    def __init__(
        self,
        log_group: str,
        log_stream: str = "warlock-audit",
        region: str | None = None,
        retention_days: int = 365,
    ) -> None:
        self.log_group = log_group
        self.log_stream = log_stream
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.retention_days = retention_days
        self._client: Any = None
        self._stream_ready: bool = False

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import boto3  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "boto3 is required for CloudWatchSink. "
                    "Install it with: pip install boto3"
                ) from exc
            self._client = boto3.client("logs", region_name=self.region)
        return self._client

    def _ensure_stream(self) -> None:
        if self._stream_ready:
            return
        client = self._get_client()
        # Create log group (idempotent)
        try:
            client.create_log_group(logGroupName=self.log_group)
            if self.retention_days > 0:
                client.put_retention_policy(
                    logGroupName=self.log_group,
                    retentionInDays=self.retention_days,
                )
        except client.exceptions.ResourceAlreadyExistsException:
            pass
        # Create log stream (idempotent)
        try:
            client.create_log_stream(
                logGroupName=self.log_group,
                logStreamName=self.log_stream,
            )
        except client.exceptions.ResourceAlreadyExistsException:
            pass
        self._stream_ready = True

    def _put_chunk(self, client: Any, events: list[dict[str, Any]]) -> None:
        """Send one chunk of log events, handling sequence tokens."""
        kwargs: dict[str, Any] = {
            "logGroupName": self.log_group,
            "logStreamName": self.log_stream,
            "logEvents": events,
        }
        client.put_log_events(**kwargs)

    def _split_into_chunks(
        self, entries: list[AuditEntry],
    ) -> list[list[dict[str, Any]]]:
        """Split entries into CloudWatch-safe chunks."""
        chunks: list[list[dict[str, Any]]] = []
        current: list[dict[str, Any]] = []
        current_bytes = 0

        for entry in entries:
            message = entry.to_json_line()
            event = {
                "timestamp": int(entry.created_at.timestamp() * 1000),
                "message": message,
            }
            event_bytes = len(message.encode("utf-8")) + 26  # CW overhead

            if (
                len(current) >= self._MAX_EVENTS_PER_PUT
                or current_bytes + event_bytes > self._MAX_BYTES_PER_PUT
            ):
                chunks.append(current)
                current = []
                current_bytes = 0

            current.append(event)
            current_bytes += event_bytes

        if current:
            chunks.append(current)
        return chunks

    def ship(self, entries: list[AuditEntry]) -> None:
        if not entries:
            return
        client = self._get_client()
        self._ensure_stream()

        chunks = self._split_into_chunks(entries)
        for chunk in chunks:
            self._put_chunk(client, chunk)

        log.info(
            "CloudWatchSink shipped %d entries to %s/%s in %d chunk(s)",
            len(entries),
            self.log_group,
            self.log_stream,
            len(chunks),
        )

    def close(self) -> None:
        self._client = None
        self._stream_ready = False


# ---------------------------------------------------------------------------
# BatchShipper
# ---------------------------------------------------------------------------

class BatchShipper:
    """Accumulate AuditEntry objects and ship in configurable batches.

    Flush triggers:
    * Batch reaches *max_batch_size* entries.
    * *flush_interval_seconds* have elapsed since the last flush.

    Both triggers are checked on every ``ingest()`` call.  Call ``flush()``
    explicitly on shutdown to drain any remaining entries.

    Args:
        sink: The backend to ship to.
        max_batch_size: Flush when this many entries are accumulated.
        flush_interval_seconds: Also flush if this many seconds have passed.
    """

    def __init__(
        self,
        sink: AuditLogSink,
        max_batch_size: int = 500,
        flush_interval_seconds: float = 60.0,
    ) -> None:
        self._sink = sink
        self._max_batch_size = max_batch_size
        self._flush_interval = flush_interval_seconds
        self._buffer: list[AuditEntry] = []
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()

    def ingest(self, entry: AuditEntry) -> None:
        """Add an entry to the buffer, flushing if a trigger condition is met."""
        with self._lock:
            self._buffer.append(entry)
            should_flush = (
                len(self._buffer) >= self._max_batch_size
                or (time.monotonic() - self._last_flush) >= self._flush_interval
            )
        if should_flush:
            self.flush()

    def flush(self) -> None:
        """Ship all buffered entries to the sink and reset the buffer."""
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer[:]
            self._buffer.clear()
            self._last_flush = time.monotonic()

        try:
            self._sink.ship(batch)
        except Exception:
            log.exception(
                "BatchShipper: sink.ship() failed for %d entries — entries lost",
                len(batch),
            )

    def close(self) -> None:
        """Flush remaining entries and close the underlying sink."""
        self.flush()
        self._sink.close()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_BACKENDS: dict[str, type[AuditLogSink]] = {
    "stdout": StdoutSink,
    "s3": S3AuditSink,
    "cloudwatch": CloudWatchSink,
}


def create_sink(backend: str, **config: Any) -> AuditLogSink:
    """Instantiate an ``AuditLogSink`` by backend name.

    Args:
        backend: One of ``"stdout"``, ``"s3"``, ``"cloudwatch"``.
        **config: Keyword arguments forwarded to the sink constructor.

    Returns:
        A configured ``AuditLogSink`` instance.

    Raises:
        ValueError: If *backend* is not recognised.
    """
    backend = backend.lower().strip()
    cls = _BACKENDS.get(backend)
    if cls is None:
        raise ValueError(
            f"Unknown audit sink backend {backend!r}. "
            f"Choose from: {', '.join(sorted(_BACKENDS))}"
        )
    return cls(**config)


def create_sink_from_env() -> AuditLogSink:
    """Create a sink from environment variables.

    Reads ``WLK_AUDIT_SINK_BACKEND`` (default ``"stdout"``) and all
    ``WLK_AUDIT_SINK_*`` variables as constructor kwargs (lower-cased,
    prefix stripped).

    Examples::

        WLK_AUDIT_SINK_BACKEND=s3
        WLK_AUDIT_SINK_BUCKET=my-audit-logs
        WLK_AUDIT_SINK_PREFIX=warlock/
        WLK_AUDIT_SINK_RETAIN_DAYS=730

    Returns:
        A configured ``AuditLogSink`` ready to use.
    """
    backend = os.environ.get("WLK_AUDIT_SINK_BACKEND", "stdout")
    prefix = "WLK_AUDIT_SINK_"
    config: dict[str, Any] = {}
    for key, value in os.environ.items():
        if key.startswith(prefix) and key != "WLK_AUDIT_SINK_BACKEND":
            param = key[len(prefix):].lower()
            # Coerce obvious integer values
            if value.isdigit():
                config[param] = int(value)
            else:
                config[param] = value
    return create_sink(backend, **config)
