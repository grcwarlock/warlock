"""Regulatory change management workflow.

Tracks regulatory changes (new regulations, framework updates, amended
requirements) and assesses their impact on existing controls and systems.

Regulatory changes are stored as AuditEntry records with
action="regulatory_change" and metadata JSON, since we cannot add new
models to the schema without a migration.

Statuses: pending -> assessed -> addressed | dismissed
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import AuditEntry, ControlResult, SystemProfile
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

_VALID_STATUSES = frozenset({"pending", "assessed", "addressed", "dismissed"})
_VALID_IMPACT_LEVELS = frozenset({"critical", "high", "medium", "low", "informational"})


# SEC-C4: ``_make_hash`` / ``_next_sequence`` produced a hash format that
# did not match :meth:`AuditTrail.verify_chain`. Routing writes through
# ``AuditTrail.record()`` instead.


def _parse_change_from_entry(entry: AuditEntry) -> dict[str, Any]:
    """Extract a regulatory change dict from an AuditEntry."""
    extra = entry.extra or {}
    created = ensure_aware(entry.created_at) if entry.created_at else None
    return {
        "id": entry.entity_id,
        "title": extra.get("title", ""),
        "framework": extra.get("framework", ""),
        "description": extra.get("description", ""),
        "effective_date": extra.get("effective_date"),
        "impact_level": extra.get("impact_level", "medium"),
        "status": extra.get("status", "pending"),
        "created_by": extra.get("created_by", entry.actor),
        "created_at": created.isoformat() if created else None,
        "addressed_by": extra.get("addressed_by"),
        "addressed_at": extra.get("addressed_at"),
        "addressed_notes": extra.get("addressed_notes"),
        "impact_assessment": extra.get("impact_assessment"),
    }


class RegulatoryChangeManager:
    """Manages regulatory change tracking and impact assessment.

    All data is stored as AuditEntry records with action="regulatory_change"
    and entity_type="regulatory_change", using the extra JSON column for
    change-specific fields.
    """

    def create_change(
        self,
        session: Session,
        title: str,
        framework: str,
        description: str,
        effective_date: str,
        impact_level: str,
        actor: str,
    ) -> dict[str, Any]:
        """Track a new regulatory change.

        Parameters
        ----------
        session : Session
            Active SQLAlchemy session.
        title : str
            Short title describing the regulatory change.
        framework : str
            Framework identifier affected (e.g. "nist_800_53").
        description : str
            Detailed description of the change.
        effective_date : str
            ISO-format date when the change takes effect.
        impact_level : str
            One of: critical, high, medium, low, informational.
        actor : str
            Identity of the person creating this record.

        Returns
        -------
        dict
            The created regulatory change record.
        """
        if impact_level not in _VALID_IMPACT_LEVELS:
            raise ValueError(
                f"Invalid impact_level '{impact_level}'. "
                f"Must be one of: {', '.join(sorted(_VALID_IMPACT_LEVELS))}"
            )

        change_id = str(uuid.uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        extra = {
            "title": title,
            "framework": framework,
            "description": description,
            "effective_date": effective_date,
            "impact_level": impact_level,
            "status": "pending",
            "created_by": actor,
            "created_at": now_iso,
        }

        from warlock.db.audit import AuditTrail

        entry = AuditTrail(session).record(
            action="regulatory_change",
            entity_type="regulatory_change",
            entity_id=change_id,
            actor=actor,
            metadata=extra,
        )

        log.info(
            "Created regulatory change %s: %s (framework=%s, impact=%s)",
            change_id[:8],
            title,
            framework,
            impact_level,
        )
        return _parse_change_from_entry(entry)

    def assess_impact(
        self,
        session: Session,
        change_id: str,
        actor: str,
    ) -> dict[str, Any]:
        """Analyze which controls and systems are affected by a regulatory change.

        Queries ControlResult and SystemProfile to determine the scope of impact.

        Parameters
        ----------
        session : Session
            Active SQLAlchemy session.
        change_id : str
            The ID of the regulatory change to assess.
        actor : str
            Identity of the person performing the assessment.

        Returns
        -------
        dict
            Impact assessment with affected controls and systems.

        Raises
        ------
        ValueError
            If the change_id is not found.
        """
        # Find the most recent entry for this change
        entry = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "regulatory_change",
                AuditEntry.entity_type == "regulatory_change",
                AuditEntry.entity_id == change_id,
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )
        if not entry:
            raise ValueError(f"Regulatory change '{change_id}' not found.")

        extra = entry.extra or {}
        framework = extra.get("framework", "")

        # Find affected controls
        affected_controls: list[dict[str, Any]] = []
        if framework:
            results = (
                session.query(
                    ControlResult.control_id,
                    ControlResult.status,
                    func.count(ControlResult.id).label("count"),
                )
                .filter(ControlResult.framework == framework)
                .group_by(ControlResult.control_id, ControlResult.status)
                .all()
            )
            control_map: dict[str, dict[str, int]] = {}
            for control_id, status, count in results:
                if control_id not in control_map:
                    control_map[control_id] = {}
                control_map[control_id][status] = count

            for control_id, statuses in sorted(control_map.items()):
                total = sum(statuses.values())
                non_compliant = statuses.get("non_compliant", 0)
                affected_controls.append(
                    {
                        "control_id": control_id,
                        "total_results": total,
                        "non_compliant": non_compliant,
                        "statuses": statuses,
                    }
                )

        # Find affected systems
        affected_systems: list[dict[str, Any]] = []
        if framework:
            systems = session.query(SystemProfile).all()
            for sp in systems:
                sp_frameworks = sp.frameworks or []
                if framework in sp_frameworks or not sp_frameworks:
                    affected_systems.append(
                        {
                            "system_id": sp.id,
                            "name": sp.name,
                            "acronym": sp.acronym or "",
                            "owner": sp.system_owner or "",
                        }
                    )

        assessment = {
            "change_id": change_id,
            "framework": framework,
            "affected_controls_count": len(affected_controls),
            "affected_controls": affected_controls[:50],  # cap for readability
            "affected_systems_count": len(affected_systems),
            "affected_systems": affected_systems,
            "assessed_by": actor,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

        # Record the assessment as a new canonical audit entry.
        from warlock.db.audit import AuditTrail

        AuditTrail(session).record(
            action="regulatory_change",
            entity_type="regulatory_change",
            entity_id=change_id,
            actor=actor,
            metadata={
                **extra,
                "status": "assessed",
                "impact_assessment": assessment,
            },
        )

        log.info(
            "Assessed regulatory change %s: %d controls, %d systems affected",
            change_id[:8],
            len(affected_controls),
            len(affected_systems),
        )
        return assessment

    def get_pending_changes(self, session: Session) -> list[dict[str, Any]]:
        """List regulatory changes not yet addressed.

        Returns changes with status 'pending' or 'assessed'.

        Parameters
        ----------
        session : Session
            Active SQLAlchemy session.

        Returns
        -------
        list[dict]
            List of pending regulatory change records.
        """
        # Get all regulatory change entries, grouped by entity_id (most recent first)
        entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "regulatory_change",
                AuditEntry.entity_type == "regulatory_change",
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

        # Deduplicate by entity_id, keeping only the most recent
        seen: set[str] = set()
        changes: list[dict[str, Any]] = []
        for entry in entries:
            if entry.entity_id in seen:
                continue
            seen.add(entry.entity_id)
            change = _parse_change_from_entry(entry)
            if change["status"] in ("pending", "assessed"):
                changes.append(change)

        return changes

    def mark_addressed(
        self,
        session: Session,
        change_id: str,
        actor: str,
        notes: str,
    ) -> dict[str, Any]:
        """Mark a regulatory change as addressed.

        Parameters
        ----------
        session : Session
            Active SQLAlchemy session.
        change_id : str
            The ID of the regulatory change to mark as addressed.
        actor : str
            Identity of the person marking this as addressed.
        notes : str
            Description of how the change was addressed.

        Returns
        -------
        dict
            The updated regulatory change record.

        Raises
        ------
        ValueError
            If the change_id is not found.
        """
        # Find the most recent entry for this change
        entry = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "regulatory_change",
                AuditEntry.entity_type == "regulatory_change",
                AuditEntry.entity_id == change_id,
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )
        if not entry:
            raise ValueError(f"Regulatory change '{change_id}' not found.")

        extra = entry.extra or {}
        now_iso = datetime.now(timezone.utc).isoformat()

        # Create a new canonical entry reflecting the addressed status.
        from warlock.db.audit import AuditTrail

        addressed_entry = AuditTrail(session).record(
            action="regulatory_change",
            entity_type="regulatory_change",
            entity_id=change_id,
            actor=actor,
            metadata={
                **extra,
                "status": "addressed",
                "addressed_by": actor,
                "addressed_at": now_iso,
                "addressed_notes": notes,
            },
        )

        log.info(
            "Marked regulatory change %s as addressed by %s",
            change_id[:8],
            actor,
        )
        return _parse_change_from_entry(addressed_entry)

    def get_change(self, session: Session, change_id: str) -> dict[str, Any] | None:
        """Get a single regulatory change by ID.

        Parameters
        ----------
        session : Session
            Active SQLAlchemy session.
        change_id : str
            The regulatory change ID.

        Returns
        -------
        dict or None
            The change record, or None if not found.
        """
        entry = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "regulatory_change",
                AuditEntry.entity_type == "regulatory_change",
                AuditEntry.entity_id == change_id,
            )
            .order_by(AuditEntry.created_at.desc())
            .first()
        )
        if not entry:
            return None
        return _parse_change_from_entry(entry)

    def list_all(self, session: Session) -> list[dict[str, Any]]:
        """List all regulatory changes, most recent first.

        Parameters
        ----------
        session : Session
            Active SQLAlchemy session.

        Returns
        -------
        list[dict]
            All regulatory change records.
        """
        entries = (
            session.query(AuditEntry)
            .filter(
                AuditEntry.action == "regulatory_change",
                AuditEntry.entity_type == "regulatory_change",
            )
            .order_by(AuditEntry.created_at.desc())
            .all()
        )

        seen: set[str] = set()
        changes: list[dict[str, Any]] = []
        for entry in entries:
            if entry.entity_id in seen:
                continue
            seen.add(entry.entity_id)
            changes.append(_parse_change_from_entry(entry))

        return changes
