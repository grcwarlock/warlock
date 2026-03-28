"""Immutable audit trail with hash chaining.

Every significant action in the pipeline is recorded as an AuditEntry.
Each entry's hash includes the previous entry's hash, creating a
tamper-evident chain that auditors can verify.

External shipping
-----------------
When ``WLK_AUDIT_SINK_BACKEND`` is set to a value other than ``"stdout"``,
``AuditTrail.record()`` additionally feeds each new entry into a module-level
``BatchShipper`` so entries are replicated to the configured sink.  The
shipper is initialised lazily on the first ``record()`` call and reused for
the lifetime of the process.  Failures in the shipper are logged and silently
swallowed so that a misconfigured sink never prevents audit writes to the DB.
"""

import hashlib
import json
import logging
import os
import threading
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import AuditEntry

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level BatchShipper — initialised once, shared across AuditTrail
# instances in the same process.
# ---------------------------------------------------------------------------

_shipper_lock = threading.Lock()
_shipper: Any = None  # BatchShipper | None


def _get_shipper() -> Any:
    """Return the process-level BatchShipper, creating it on first call.

    Returns ``None`` when external shipping is not configured (i.e.
    ``WLK_AUDIT_SINK_BACKEND`` is absent or set to ``"stdout"``).
    """
    global _shipper  # noqa: PLW0603
    if _shipper is not None:
        return _shipper
    audit_backend = os.environ.get("WLK_AUDIT_SINK_BACKEND", "").strip().lower()
    if not audit_backend or audit_backend == "stdout":
        return None
    with _shipper_lock:
        if _shipper is not None:
            return _shipper
        try:
            from warlock.export.audit_sink import BatchShipper, create_sink_from_env

            sink = create_sink_from_env()
            _shipper = BatchShipper(sink)
            log.info("AuditTrail: BatchShipper initialised with %r sink", audit_backend)
        except Exception:
            log.exception(
                "AuditTrail: failed to initialise BatchShipper for backend %r — "
                "external shipping disabled",
                audit_backend,
            )
            _shipper = None
    return _shipper


class AuditTrail:
    def __init__(self, session: Session):
        self.session = session

    def record(
        self,
        action: str,
        entity_type: str,
        entity_id: str,
        actor: str = "pipeline",
        evidence_sha256: str = "",
        metadata: dict | None = None,
    ) -> AuditEntry:
        """Record an action in the immutable audit trail.

        Uses DB-level SELECT ... FOR UPDATE to serialise sequence assignment
        across multiple workers/processes.  The row lock on the most recent
        audit entry prevents concurrent transactions from reading the same
        sequence number.  The flush is performed inside the same transaction
        so that the new row is visible to the next ``FOR UPDATE`` reader
        before the application-level call returns.
        """
        # Get the last entry for chain linking.
        # with_for_update() acquires a row-level lock in PostgreSQL,
        # preventing concurrent workers from reading the same sequence.
        # In SQLite (single-writer), this is a no-op but safe.
        last = (
            self.session.query(AuditEntry)
            .order_by(AuditEntry.sequence.desc())
            .with_for_update()
            .first()
        )

        prev_hash = last.entry_hash if last else "genesis"
        sequence = int(last.sequence + 1) if last else 1

        # Compute this entry's hash (includes previous hash for chaining).
        # Timestamp is deliberately excluded so verify_chain() can recompute
        # the hash deterministically from stored columns.
        content = json.dumps(
            {
                "sequence": sequence,
                "previous_hash": prev_hash,
                "action": action,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "actor": actor,
                "evidence_sha256": evidence_sha256 or "",
            },
            sort_keys=True,
        )
        entry_hash = hashlib.sha256(content.encode()).hexdigest()

        entry = AuditEntry(
            sequence=sequence,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=actor,
            evidence_sha256=evidence_sha256,
            extra=metadata or {},
        )
        self.session.add(entry)
        # Flush inside the transaction so the new row's FOR UPDATE lock is
        # visible to the next concurrent reader before we release control.
        self.session.flush()

        # Ship to external sink outside the DB lock so a slow/failing sink
        # does not block audit writes or hold the lock longer than necessary.
        shipper = _get_shipper()
        if shipper is not None:
            try:
                from warlock.export.audit_sink import (
                    AuditEntry as SinkAuditEntry,
                )
                from datetime import timezone

                created_at = entry.created_at
                if created_at is None:
                    from datetime import datetime

                    created_at = datetime.now(timezone.utc)
                elif created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)

                sink_entry = SinkAuditEntry(
                    id=entry.id,
                    sequence=entry.sequence,
                    previous_hash=entry.previous_hash,
                    entry_hash=entry.entry_hash,
                    action=entry.action,
                    entity_type=entry.entity_type,
                    entity_id=entry.entity_id,
                    actor=entry.actor,
                    created_at=created_at,
                    evidence_sha256=entry.evidence_sha256 or None,
                    extra=entry.extra or {},
                )
                shipper.ingest(sink_entry)
            except Exception:
                log.exception(
                    "AuditTrail: BatchShipper.ingest() failed for sequence %d — "
                    "DB write is unaffected",
                    entry.sequence,
                )

        return entry

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the entire audit chain is intact. Returns (valid, errors).

        Uses yield_per(500) to stream results instead of loading the entire
        audit trail into memory at once, preventing OOM on large chains.
        """
        entries = self.session.query(AuditEntry).order_by(AuditEntry.sequence.asc()).yield_per(500)

        errors: list[str] = []
        prev_hash = "genesis"

        for entry in entries:
            if entry.previous_hash != prev_hash:
                errors.append(
                    f"Chain broken at sequence {entry.sequence}: "
                    f"expected prev_hash={prev_hash}, got {entry.previous_hash}"
                )

            # Recompute hash from the same fields used in record()
            content = json.dumps(
                {
                    "sequence": int(entry.sequence),
                    "previous_hash": entry.previous_hash,
                    "action": entry.action,
                    "entity_type": entry.entity_type,
                    "entity_id": entry.entity_id,
                    "actor": entry.actor,
                    "evidence_sha256": entry.evidence_sha256 or "",
                },
                sort_keys=True,
            )
            expected_hash = hashlib.sha256(content.encode()).hexdigest()

            if entry.entry_hash != expected_hash:
                errors.append(
                    f"Hash mismatch at sequence {entry.sequence}: "
                    f"stored={entry.entry_hash}, computed={expected_hash}"
                )

            prev_hash = entry.entry_hash

        return (len(errors) == 0, errors)
