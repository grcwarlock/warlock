"""Control inheritance modeling.

Maps control responsibility (inherited, shared, common, system_specific)
per NIST SP 800-53A and FedRAMP CRM. Resolves provider posture for
inherited controls.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from warlock.db.models import ControlInheritance, PostureSnapshot

log = logging.getLogger(__name__)


class InheritanceManager:
    """Manages control inheritance relationships between systems."""

    def set_inheritance(
        self,
        session: Session,
        system_profile_id: str,
        framework: str,
        control_id: str,
        inheritance_type: str,
        provider_system_id: str | None = None,
        provider_description: str | None = None,
        responsibility_description: str | None = None,
        evidence_requirement: str = "both",
        status: str = "active",
    ) -> ControlInheritance:
        """Create or update a control inheritance record.

        Uses upsert semantics on the unique (system_profile_id, framework,
        control_id) constraint.

        Args:
            session: SQLAlchemy session.
            system_profile_id: Consumer system ID.
            framework: Framework identifier.
            control_id: Control identifier.
            inheritance_type: One of inherited, shared, common, system_specific.
            provider_system_id: System that provides the control (for inherited/shared).
            provider_description: Description of what the provider covers.
            responsibility_description: What the consumer must implement.
            evidence_requirement: provider_only, consumer_only, or both.
            status: active, under_review, or deprecated.

        Returns:
            Created or updated ControlInheritance.
        """
        existing = (
            session.query(ControlInheritance)
            .filter(
                ControlInheritance.system_profile_id == system_profile_id,
                ControlInheritance.framework == framework,
                ControlInheritance.control_id == control_id,
            )
            .first()
        )

        if existing:
            existing.inheritance_type = inheritance_type
            existing.provider_system_id = provider_system_id
            existing.provider_description = provider_description
            existing.responsibility_description = responsibility_description
            existing.evidence_requirement = evidence_requirement
            existing.status = status
            session.flush()
            log.info(
                "Updated inheritance for system=%s %s/%s -> %s",
                system_profile_id,
                framework,
                control_id,
                inheritance_type,
            )
            return existing

        ci = ControlInheritance(
            system_profile_id=system_profile_id,
            framework=framework,
            control_id=control_id,
            inheritance_type=inheritance_type,
            provider_system_id=provider_system_id,
            provider_description=provider_description,
            responsibility_description=responsibility_description,
            evidence_requirement=evidence_requirement,
            status=status,
        )
        session.add(ci)
        session.flush()

        log.info(
            "Created inheritance for system=%s %s/%s -> %s (provider=%s)",
            system_profile_id,
            framework,
            control_id,
            inheritance_type,
            provider_system_id,
        )
        return ci

    def get_for_system(
        self,
        session: Session,
        system_profile_id: str,
        framework: str | None = None,
    ) -> list[ControlInheritance]:
        """Get all inheritance records for a system.

        Args:
            session: SQLAlchemy session.
            system_profile_id: System to query.
            framework: Optional framework filter.

        Returns:
            List of ControlInheritance rows.
        """
        query = session.query(ControlInheritance).filter(
            ControlInheritance.system_profile_id == system_profile_id,
            ControlInheritance.status == "active",
        )
        if framework:
            query = query.filter(ControlInheritance.framework == framework)

        return query.order_by(
            ControlInheritance.framework,
            ControlInheritance.control_id,
        ).all()

    def get_inherited_status(
        self,
        session: Session,
        system_profile_id: str,
        framework: str,
        control_id: str,
    ) -> str | None:
        """Check the provider's posture for an inherited control.

        For controls with inheritance_type=inherited and
        evidence_requirement=provider_only, looks up the provider system's
        latest posture snapshot.

        Args:
            session: SQLAlchemy session.
            system_profile_id: Consumer system ID.
            framework: Framework identifier.
            control_id: Control identifier.

        Returns:
            "inherited_compliant" if provider is compliant,
            "inherited_at_risk" if provider is non-compliant or has no data,
            None if the control is not inherited or not provider_only.
        """
        ci = (
            session.query(ControlInheritance)
            .filter(
                ControlInheritance.system_profile_id == system_profile_id,
                ControlInheritance.framework == framework,
                ControlInheritance.control_id == control_id,
                ControlInheritance.status == "active",
            )
            .first()
        )

        if not ci:
            return None
        if ci.inheritance_type != "inherited":
            return None
        if ci.evidence_requirement != "provider_only":
            return None
        if not ci.provider_system_id:
            return "inherited_at_risk"

        # Look up provider's latest snapshot for this control
        provider_snapshot = (
            session.query(PostureSnapshot)
            .filter(
                PostureSnapshot.system_profile_id == ci.provider_system_id,
                PostureSnapshot.framework == framework,
                PostureSnapshot.control_id == control_id,
            )
            .order_by(PostureSnapshot.snapshot_date.desc())
            .first()
        )

        if not provider_snapshot:
            log.warning(
                "No provider snapshot for system=%s %s/%s",
                ci.provider_system_id,
                framework,
                control_id,
            )
            return "inherited_at_risk"

        if provider_snapshot.status == "compliant":
            return "inherited_compliant"

        return "inherited_at_risk"
