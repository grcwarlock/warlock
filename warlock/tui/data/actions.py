"""Write operations for the TUI.

Uses get_session() for writes. Follows existing patterns
(POAMManager for POA&M transitions, etc.)
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.db.engine import get_session, init_db
from warlock.db.models import Remediation


def transition_remediation(rem_id: str, new_status: str, actor: str) -> str | None:
    """Transition a remediation's status. Returns error message or None."""
    valid = {
        "open": ["assigned"],
        "assigned": ["in_progress", "open"],
        "in_progress": ["verification", "assigned"],
        "verification": ["closed", "in_progress"],
        "closed": [],
    }
    init_db()
    with get_session() as session:
        r = session.query(Remediation).filter(Remediation.id == rem_id).first()
        if not r:
            return f"Remediation {rem_id} not found"
        allowed = valid.get(r.status, [])
        if new_status not in allowed:
            return f"Cannot transition from {r.status} to {new_status}. Valid: {allowed}"
        r.status = new_status
        r.updated_at = datetime.now(timezone.utc)
        if new_status == "assigned" and not r.assigned_to:
            r.assigned_to = actor
            r.assigned_by = actor
            r.assigned_at = datetime.now(timezone.utc)
        if new_status == "closed":
            r.closed_at = datetime.now(timezone.utc)
        if new_status == "verification":
            r.verified_by = actor
            r.verified_at = datetime.now(timezone.utc)
    return None


def assign_remediation(rem_id: str, assignee: str, actor: str) -> str | None:
    """Assign a remediation. Returns error message or None."""
    init_db()
    with get_session() as session:
        r = session.query(Remediation).filter(Remediation.id == rem_id).first()
        if not r:
            return f"Remediation {rem_id} not found"
        r.assigned_to = assignee
        r.assigned_by = actor
        r.assigned_at = datetime.now(timezone.utc)
        if r.status == "open":
            r.status = "assigned"
        r.updated_at = datetime.now(timezone.utc)
    return None
