"""GAP-082: System authorization state machine.

Enforces valid transitions on SystemProfile.authorization_status with
audit trail logging.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import SystemProfile

log = logging.getLogger(__name__)

VALID_AUTH_TRANSITIONS: dict[str, set[str]] = {
    "not_started": {"in_assessment"},
    "in_assessment": {"authorized", "denied"},
    "authorized": {"in_reassessment", "revoked"},
    "in_reassessment": {"authorized", "revoked"},
    "denied": {"in_assessment"},
    "revoked": {"in_assessment"},
}


def transition_authorization(
    session: Session,
    system_id: str,
    target: str,
    actor: str,
    notes: str | None = None,
) -> dict[str, Any]:
    """Transition a system's authorization status with state machine enforcement.

    Args:
        session: SQLAlchemy session.
        system_id: SystemProfile UUID.
        target: Target authorization status.
        actor: Identity performing the transition.
        notes: Optional notes.

    Returns:
        Dict with old_status, new_status, transitioned_at.

    Raises:
        ValueError: If system not found or transition is invalid.
    """
    system = session.query(SystemProfile).filter_by(id=system_id).first()
    if not system:
        raise ValueError(f"System profile not found: {system_id}")

    current = system.authorization_status or "not_started"

    # Normalise legacy values
    if current == "not_authorized":
        current = "not_started"
    elif current == "in_process":
        current = "in_assessment"

    valid_targets = VALID_AUTH_TRANSITIONS.get(current, set())
    if target not in valid_targets:
        raise ValueError(
            f"Cannot transition from '{current}' to '{target}'. "
            f"Valid targets: {sorted(valid_targets) if valid_targets else 'none'}"
        )

    now = datetime.now(timezone.utc)
    old_status = current
    system.authorization_status = target

    if target == "authorized":
        system.authorization_date = now
    elif target == "revoked":
        system.authorization_expiry = now

    session.flush()

    audit = AuditTrail(session)
    audit.record(
        action="system_authorization_transition",
        entity_type="system_profile",
        entity_id=system_id,
        actor=actor,
        metadata={
            "old_status": old_status,
            "new_status": target,
            "notes": notes,
        },
    )

    log.info(
        "System %s authorization: %s -> %s by %s",
        system.name,
        old_status,
        target,
        actor,
    )
    return {
        "system_id": system_id,
        "system_name": system.name,
        "old_status": old_status,
        "new_status": target,
        "transitioned_at": now.isoformat(),
        "actor": actor,
        "notes": notes,
    }
