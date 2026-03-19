"""Immutable audit trail with hash chaining.

Every significant action in the pipeline is recorded as an AuditEntry.
Each entry's hash includes the previous entry's hash, creating a
tamper-evident chain that auditors can verify.
"""

import hashlib
import json
import threading

from sqlalchemy.orm import Session

from warlock.db.models import AuditEntry

_audit_lock = threading.Lock()


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
        """Record an action in the immutable audit trail."""
        with _audit_lock:
            # Get the last entry for chain linking
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
                    "evidence_sha256": evidence_sha256,
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
            return entry

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the entire audit chain is intact. Returns (valid, errors)."""
        entries = (
            self.session.query(AuditEntry)
            .order_by(AuditEntry.sequence.asc())
            .all()
        )

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
