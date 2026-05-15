"""External hash chain anchor — publish and verify chain head externally.

Writes the latest ``AuditEntry.entry_hash`` to a file (or future S3/DB)
so an external party can verify the audit chain has not been tampered with.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from warlock.db.models import AuditEntry


def _recompute_entry_hash(entry: AuditEntry) -> str:
    """Recompute the canonical content hash for an AuditEntry row.

    Must stay byte-identical to ``AuditTrail.record()`` and
    ``AuditTrail.verify_chain()`` (``warlock/db/audit.py``). Used by the
    anchor verifier so a row whose ``entry_hash`` column was tampered
    without touching ``previous_hash`` linkage is still detected.
    """
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
        default=str,
    )
    return hashlib.sha256(content.encode()).hexdigest()


log = logging.getLogger(__name__)

_DEFAULT_ANCHOR_FILE = "warlock_chain_anchor.json"


class ChainAnchor:
    """Publish and verify the audit trail hash chain head."""

    def publish(
        self,
        session: Session,
        target: str = "file",
        path: str = "",
    ) -> dict[str, str]:
        """Publish current chain head hash to external storage.

        Parameters
        ----------
        session:
            Database session to read the latest AuditEntry.
        target:
            Storage target — currently ``"file"`` is supported.
        path:
            File path for the anchor.  Defaults to ``warlock_chain_anchor.json``
            in the current directory.

        Returns
        -------
        dict with ``chain_head``, ``sequence``, ``published_at`` keys.
        """
        latest = session.query(AuditEntry).order_by(AuditEntry.sequence.desc()).first()
        if latest is None:
            raise ValueError("No audit entries found — chain is empty")

        anchor_data = {
            "chain_head": latest.entry_hash,
            "sequence": int(latest.sequence),
            "entry_id": latest.id,
            "published_at": datetime.now(timezone.utc).isoformat(),
        }

        if target == "file":
            anchor_path = path or _DEFAULT_ANCHOR_FILE
            Path(anchor_path).write_text(json.dumps(anchor_data, indent=2) + "\n")
            log.info(
                "Chain anchor published to %s (seq=%d, hash=%s)",
                anchor_path,
                anchor_data["sequence"],
                anchor_data["chain_head"][:16],
            )
        else:
            raise ValueError(f"Unsupported anchor target: {target}")

        return anchor_data

    def verify_anchor(
        self,
        session: Session,
        target: str = "file",
        path: str = "",
    ) -> dict[str, object]:
        """Compare stored anchor against current chain head.

        Returns
        -------
        dict with ``valid`` (bool), ``stored``, ``current`` anchor data.
        """
        if target == "file":
            anchor_path = path or _DEFAULT_ANCHOR_FILE
            if not os.path.exists(anchor_path):
                return {
                    "valid": False,
                    "error": f"Anchor file not found: {anchor_path}",
                }
            stored = json.loads(Path(anchor_path).read_text())
        else:
            raise ValueError(f"Unsupported anchor target: {target}")

        # Look up the entry at the stored sequence
        entry = session.query(AuditEntry).filter(AuditEntry.sequence == stored["sequence"]).first()
        if entry is None:
            return {
                "valid": False,
                "error": f"No audit entry at sequence {stored['sequence']}",
                "stored": stored,
            }

        # SEC-C7: Recompute the content hash from the row's columns rather
        # than trusting ``entry.entry_hash``. An attacker with DB write
        # access who modifies ``action``/``entity_id``/``actor``/``extra``/
        # ``evidence_sha256`` *and* updates ``entry_hash`` to match the new
        # content would still be caught by chain-link verification; but an
        # attacker who modifies *only* the content fields and leaves
        # ``entry_hash`` alone was previously not detected by this anchor.
        recomputed = _recompute_entry_hash(entry)
        stored_matches_db = entry.entry_hash == stored["chain_head"]
        recomputed_matches_db = recomputed == entry.entry_hash
        match = stored_matches_db and recomputed_matches_db

        result: dict[str, object] = {
            "valid": match,
            "stored_hash": stored["chain_head"],
            "current_hash": entry.entry_hash,
            "recomputed_hash": recomputed,
            "sequence": stored["sequence"],
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
        if not match:
            if not stored_matches_db:
                err = "Anchor mismatch — chain head differs from stored value"
            else:
                err = (
                    "Hash mismatch — row content does not produce the stored "
                    "entry_hash (entry_hash column was tampered or content was "
                    "modified without rehashing)"
                )
            result["error"] = err
            log.warning(
                "Chain anchor verification FAILED at seq=%d: stored=%s db=%s recomputed=%s",
                stored["sequence"],
                stored["chain_head"][:16],
                entry.entry_hash[:16],
                recomputed[:16],
            )
        else:
            log.info(
                "Chain anchor verified at seq=%d",
                stored["sequence"],
            )
        return result
