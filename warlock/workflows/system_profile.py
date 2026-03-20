"""System profile and authorization boundary management."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlResult,
    Finding,
    SystemProfile,
)
from warlock.utils import ensure_aware


class SystemProfileManager:
    """Manages system profiles (authorization boundaries) for assessment scoping."""

    VALID_IMPACT_LEVELS = {"low", "moderate", "high"}
    VALID_AUTH_STATUSES = {
        "not_authorized",
        "in_process",
        "authorized",
        "denied",
        "revoked",
    }

    def create(
        self,
        session: Session,
        name: str,
        description: str,
        **kwargs: Any,
    ) -> SystemProfile:
        """Create a new system profile."""
        # Validate impact levels if provided
        for field in (
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
            "overall_impact",
        ):
            if field in kwargs and kwargs[field] not in self.VALID_IMPACT_LEVELS:
                raise ValueError(
                    f"Invalid {field}: {kwargs[field]}. Must be one of {self.VALID_IMPACT_LEVELS}"
                )

        if "authorization_status" in kwargs:
            if kwargs["authorization_status"] not in self.VALID_AUTH_STATUSES:
                raise ValueError(
                    f"Invalid authorization_status: {kwargs['authorization_status']}. "
                    f"Must be one of {self.VALID_AUTH_STATUSES}"
                )

        profile = SystemProfile(
            name=name,
            description=description,
            **kwargs,
        )
        session.add(profile)
        session.flush()
        return profile

    def update(
        self,
        session: Session,
        profile_id: str,
        **kwargs: Any,
    ) -> SystemProfile:
        """Update a system profile."""
        profile = session.query(SystemProfile).filter(SystemProfile.id == profile_id).first()
        if not profile:
            raise ValueError(f"System profile not found: {profile_id}")

        # Validate impact levels if being updated
        for field in (
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
            "overall_impact",
        ):
            if field in kwargs and kwargs[field] not in self.VALID_IMPACT_LEVELS:
                raise ValueError(
                    f"Invalid {field}: {kwargs[field]}. Must be one of {self.VALID_IMPACT_LEVELS}"
                )

        if "authorization_status" in kwargs:
            if kwargs["authorization_status"] not in self.VALID_AUTH_STATUSES:
                raise ValueError(
                    f"Invalid authorization_status: {kwargs['authorization_status']}. "
                    f"Must be one of {self.VALID_AUTH_STATUSES}"
                )

        for key, value in kwargs.items():
            if hasattr(profile, key):
                setattr(profile, key, value)

        profile.updated_at = datetime.now(timezone.utc)
        session.flush()
        return profile

    def get(
        self,
        session: Session,
        profile_id: str,
    ) -> SystemProfile | None:
        """Get a system profile by ID."""
        return session.query(SystemProfile).filter(SystemProfile.id == profile_id).first()

    def list_active(
        self,
        session: Session,
    ) -> list[SystemProfile]:
        """List all active system profiles."""
        return (
            session.query(SystemProfile)
            .filter(SystemProfile.is_active == True)  # noqa: E712
            .order_by(SystemProfile.name)
            .all()
        )

    def scope_findings(
        self,
        session: Session,
        profile_id: str,
    ) -> list[Finding]:
        """Return only findings that belong to this system's boundary.

        Filters by connector_scope (which providers) and cloud_accounts
        (which account_ids).
        """
        profile = self.get(session, profile_id)
        if not profile:
            raise ValueError(f"System profile not found: {profile_id}")

        query = session.query(Finding)

        # Filter by connector scope (provider/source)
        connector_scope = profile.connector_scope or []
        if connector_scope:
            query = query.filter(Finding.source.in_(connector_scope))

        # Filter by cloud accounts
        cloud_accounts = profile.cloud_accounts or []
        account_ids = [acc.get("account_id") for acc in cloud_accounts if acc.get("account_id")]
        if account_ids:
            query = query.filter(Finding.account_id.in_(account_ids))

        return query.order_by(Finding.observed_at.desc()).all()

    def scope_results(
        self,
        session: Session,
        profile_id: str,
        framework: str | None = None,
    ) -> list[ControlResult]:
        """Return only control results within this system's boundary."""
        profile = self.get(session, profile_id)
        if not profile:
            raise ValueError(f"System profile not found: {profile_id}")

        # Get finding IDs in scope
        scoped_findings = self.scope_findings(session, profile_id)
        finding_ids = [f.id for f in scoped_findings]

        if not finding_ids:
            return []

        query = session.query(ControlResult).filter(ControlResult.finding_id.in_(finding_ids))

        if framework:
            query = query.filter(ControlResult.framework == framework)

        # Also filter by applicable frameworks from the profile
        applicable_frameworks = profile.frameworks or []
        if applicable_frameworks and not framework:
            query = query.filter(ControlResult.framework.in_(applicable_frameworks))

        return query.order_by(ControlResult.assessed_at.desc()).all()

    def posture_for_system(
        self,
        session: Session,
        profile_id: str,
        framework: str,
    ) -> dict[str, Any]:
        """Calculate posture score scoped to this system only."""
        results = self.scope_results(session, profile_id, framework=framework)

        if not results:
            return {
                "framework": framework,
                "total": 0,
                "compliant": 0,
                "non_compliant": 0,
                "partial": 0,
                "not_assessed": 0,
                "posture_score": 0.0,
            }

        total = len(results)
        compliant = sum(1 for r in results if r.status == "compliant")
        non_compliant = sum(1 for r in results if r.status == "non_compliant")
        partial = sum(1 for r in results if r.status == "partial")
        not_assessed = sum(1 for r in results if r.status in ("not_assessed", "not_applicable"))

        # Score: compliant = 100, partial = 50, non_compliant = 0, not_assessed = 0
        assessed = total - not_assessed
        if assessed > 0:
            score = ((compliant * 100) + (partial * 50)) / assessed
        else:
            score = 0.0

        return {
            "framework": framework,
            "total": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "not_assessed": not_assessed,
            "posture_score": round(score, 2),
        }

    def generate_ssp_header(
        self,
        profile: SystemProfile,
    ) -> dict[str, Any]:
        """Generate OSCAL SSP system-characteristics from profile data.

        Returns dict compatible with the OSCAL export's system-characteristics structure.
        """
        # Build security impact level
        security_impact_level = {
            "security-objective-confidentiality": profile.confidentiality_impact or "moderate",
            "security-objective-integrity": profile.integrity_impact or "moderate",
            "security-objective-availability": profile.availability_impact or "moderate",
        }

        # Build system information
        system_info = {
            "system-name": profile.name,
            "system-name-short": profile.acronym or "",
            "description": profile.description or "",
            "security-sensitivity-level": profile.overall_impact or "moderate",
            "security-impact-level": security_impact_level,
        }

        # Build authorization boundary
        auth_boundary = {
            "description": profile.description or f"Authorization boundary for {profile.name}",
        }

        # Build network architecture from network_boundaries
        network_arch = {
            "description": "Network architecture",
            "diagrams": [],
        }
        for boundary in profile.network_boundaries or []:
            network_arch["diagrams"].append(
                {
                    "description": boundary.get("description", ""),
                    "cidr": boundary.get("cidr", ""),
                }
            )

        # Build responsible parties
        responsible_parties = []
        if profile.system_owner:
            responsible_parties.append(
                {
                    "role-id": "system-owner",
                    "party-uuid": profile.system_owner,
                    "email": profile.system_owner_email or "",
                }
            )
        if profile.isso:
            responsible_parties.append(
                {
                    "role-id": "isso",
                    "party-uuid": profile.isso,
                    "email": profile.isso_email or "",
                }
            )
        if profile.issm:
            responsible_parties.append(
                {
                    "role-id": "issm",
                    "party-uuid": profile.issm,
                    "email": profile.issm_email or "",
                }
            )
        if profile.authorizing_official:
            responsible_parties.append(
                {
                    "role-id": "authorizing-official",
                    "party-uuid": profile.authorizing_official,
                    "email": profile.ao_email or "",
                }
            )

        # Build interconnections (leveraged authorizations)
        leveraged_authorizations = []
        for conn in profile.interconnections or []:
            leveraged_authorizations.append(
                {
                    "title": conn.get("system_name", ""),
                    "description": f"Direction: {conn.get('direction', 'N/A')}. "
                    f"Data types: {', '.join(conn.get('data_types', []))}",
                }
            )

        return {
            "system-characteristics": {
                "system-information": system_info,
                "authorization-boundary": auth_boundary,
                "network-architecture": network_arch,
                "responsible-parties": responsible_parties,
                "leveraged-authorizations": leveraged_authorizations,
                "status": {
                    "state": profile.authorization_status or "not_authorized",
                    "authorization-date": (
                        profile.authorization_date.isoformat()
                        if profile.authorization_date
                        else None
                    ),
                },
                "deployment-model": profile.deployment_model or "cloud",
                "service-model": profile.service_model or "IaaS",
            },
        }

    def check_authorization_expiry(
        self,
        session: Session,
    ) -> list[SystemProfile]:
        """Return systems with authorization expiring within 90 days."""
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(days=90)

        rows = (
            session.query(SystemProfile)
            .filter(
                SystemProfile.is_active == True,  # noqa: E712
                SystemProfile.authorization_status == "authorized",
                SystemProfile.authorization_expiry != None,  # noqa: E711
            )
            .order_by(SystemProfile.authorization_expiry.asc())
            .all()
        )
        # W-4: ensure_aware before comparing authorization_expiry
        return [sp for sp in rows if ensure_aware(sp.authorization_expiry) <= cutoff]
