"""External hash chain anchor — publish and verify chain head externally.

Writes the latest ``AuditEntry.entry_hash`` to a file (or future S3/DB)
so an external party can verify the audit chain has not been tampered with.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from warlock.db.models import AuditEntry

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

        match = entry.entry_hash == stored["chain_head"]
        result: dict[str, object] = {
            "valid": match,
            "stored_hash": stored["chain_head"],
            "current_hash": entry.entry_hash,
            "sequence": stored["sequence"],
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }
        if not match:
            result["error"] = "Hash mismatch — chain may have been tampered with"
            log.warning(
                "Chain anchor verification FAILED at seq=%d: stored=%s current=%s",
                stored["sequence"],
                stored["chain_head"][:16],
                entry.entry_hash[:16],
            )
        else:
            log.info(
                "Chain anchor verified at seq=%d",
                stored["sequence"],
            )
        return result
