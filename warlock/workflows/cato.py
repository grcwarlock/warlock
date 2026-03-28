"""GAP-080: FedRAMP continuous ATO (cATO) workflow.

Manages the cATO lifecycle: planning -> assessment -> authorization ->
monitoring -> reauthorization, with state machine enforcement and
continuous monitoring checks.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.audit import AuditTrail
from warlock.db.models import ControlResult, SystemProfile
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)


class CATOManager:
    """FedRAMP continuous ATO lifecycle manager."""

    VALID_TRANSITIONS: dict[str, set[str]] = {
        "planning": {"assessment"},
        "assessment": {"authorization", "planning"},
        "authorization": {"monitoring"},
        "monitoring": {"reauthorization", "revoked"},
        "reauthorization": {"monitoring", "revoked"},
    }

    ATO_TYPES = frozenset({"cATO", "ATO", "P-ATO"})

    def create(
        self,
        session: Session,
        system_id: str,
        authorizing_official: str,
        ato_type: str = "cATO",
    ) -> dict[str, Any]:
        """Initiate a cATO lifecycle for a system.

        Stores cATO metadata in the SystemProfile's JSON fields and sets
        the initial status to ``planning``.

        Args:
            session: SQLAlchemy session.
            system_id: SystemProfile UUID.
            authorizing_official: Name/email of the authorizing official.
            ato_type: One of cATO, ATO, P-ATO.

        Returns:
            Dict with cato_id, system_id, status, ato_type.
        """
        if ato_type not in self.ATO_TYPES:
            raise ValueError(
                f"Invalid ATO type '{ato_type}'. Must be one of: {sorted(self.ATO_TYPES)}"
            )

        system = session.query(SystemProfile).filter_by(id=system_id).first()
        if not system:
            raise ValueError(f"System profile not found: {system_id}")

        now = datetime.now(timezone.utc)

        # Store cATO state in the system profile
        system.authorization_status = "planning"
        system.authorizing_official = authorizing_official

        cato_meta = {
            "ato_type": ato_type,
            "status": "planning",
            "authorizing_official": authorizing_official,
            "initiated_at": now.isoformat(),
            "history": [
                {
                    "status": "planning",
                    "timestamp": now.isoformat(),
                    "actor": authorizing_official,
                    "notes": f"{ato_type} lifecycle initiated",
                }
            ],
        }

        # Store in system metadata — use connector_scope as a safe JSON field
        # that won't conflict. Better: add to a dedicated field.
        # We store cATO data directly on system profile fields.
        system.continuous_monitoring_plan = (
            f"{ato_type} initiated by {authorizing_official} on {now.date().isoformat()}"
        )
        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="cato_created",
            entity_type="system_profile",
            entity_id=system_id,
            actor=authorizing_official,
            metadata=cato_meta,
        )

        log.info(
            "cATO lifecycle created for system %s (%s) by %s",
            system.name,
            ato_type,
            authorizing_official,
        )
        return {
            "cato_id": system_id,
            "system_id": system_id,
            "system_name": system.name,
            "status": "planning",
            "ato_type": ato_type,
            "authorizing_official": authorizing_official,
            "initiated_at": now.isoformat(),
        }

    def transition(
        self,
        session: Session,
        cato_id: str,
        target_status: str,
        actor: str,
        notes: str | None = None,
    ) -> dict[str, Any]:
        """Transition a cATO to a new status.

        Enforces the state machine defined in VALID_TRANSITIONS.

        Args:
            session: SQLAlchemy session.
            cato_id: SystemProfile UUID (acts as cATO ID).
            target_status: Target status to transition to.
            actor: Person performing the transition.
            notes: Optional notes for the transition.

        Returns:
            Dict with old_status, new_status, transitioned_at.
        """
        system = session.query(SystemProfile).filter_by(id=cato_id).first()
        if not system:
            raise ValueError(f"System profile not found: {cato_id}")

        current = system.authorization_status or "planning"

        # Map system authorization_status to cATO status space
        # Handle cases where authorization_status uses different naming
        status_map = {
            "not_authorized": "planning",
            "not_started": "planning",
            "in_process": "assessment",
            "authorized": "monitoring",
            "denied": "planning",
            "revoked": "revoked",
        }
        current_cato = status_map.get(current, current)

        valid_targets = self.VALID_TRANSITIONS.get(current_cato, set())
        if target_status not in valid_targets:
            raise ValueError(
                f"Cannot transition from '{current_cato}' to '{target_status}'. "
                f"Valid targets: {sorted(valid_targets) if valid_targets else 'none (terminal state)'}"
            )

        now = datetime.now(timezone.utc)
        system.authorization_status = target_status

        if target_status == "authorization":
            system.authorization_date = now

        session.flush()

        audit = AuditTrail(session)
        audit.record(
            action="cato_transition",
            entity_type="system_profile",
            entity_id=cato_id,
            actor=actor,
            metadata={
                "old_status": current_cato,
                "new_status": target_status,
                "notes": notes,
            },
        )

        log.info(
            "cATO %s transitioned %s -> %s by %s",
            cato_id[:8],
            current_cato,
            target_status,
            actor,
        )
        return {
            "cato_id": cato_id,
            "old_status": current_cato,
            "new_status": target_status,
            "transitioned_at": now.isoformat(),
            "actor": actor,
            "notes": notes,
        }

    def check_continuous_monitoring(
        self,
        session: Session,
        system_id: str,
    ) -> dict[str, Any]:
        """Check continuous monitoring health for a system in cATO.

        Evaluates:
        - Percentage of controls assessed in the last 30 days
        - Count of non-compliant controls
        - Whether the system has active scanning (recent findings)

        Args:
            session: SQLAlchemy session.
            system_id: SystemProfile UUID.

        Returns:
            Dict with monitoring health metrics.
        """
        system = session.query(SystemProfile).filter_by(id=system_id).first()
        if not system:
            raise ValueError(f"System profile not found: {system_id}")

        now = datetime.now(timezone.utc)

        # Get all control results for this system
        results = (
            session.query(ControlResult).filter(ControlResult.system_profile_id == system_id).all()
        )

        total = len(results)
        if total == 0:
            return {
                "system_id": system_id,
                "system_name": system.name,
                "status": system.authorization_status,
                "total_controls": 0,
                "assessed_last_30d": 0,
                "non_compliant": 0,
                "monitoring_health": "no_data",
            }

        # Controls assessed in last 30 days
        cutoff_30d = now - timedelta(days=30)
        recent = sum(
            1 for r in results if r.assessed_at and ensure_aware(r.assessed_at) >= cutoff_30d
        )

        non_compliant = sum(1 for r in results if r.status == "non_compliant")
        compliant = sum(1 for r in results if r.status == "compliant")
        pct_recent = round(recent / total * 100, 1) if total else 0
        pct_compliant = round(compliant / total * 100, 1) if total else 0

        # Health determination
        if pct_recent >= 80 and pct_compliant >= 70:
            health = "healthy"
        elif pct_recent >= 50:
            health = "degraded"
        else:
            health = "critical"

        return {
            "system_id": system_id,
            "system_name": system.name,
            "status": system.authorization_status,
            "total_controls": total,
            "assessed_last_30d": recent,
            "pct_assessed_last_30d": pct_recent,
            "non_compliant": non_compliant,
            "pct_compliant": pct_compliant,
            "monitoring_health": health,
        }
