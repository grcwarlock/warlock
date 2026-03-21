"""BitSight normalizer — transforms raw BitSight API responses into Findings.

Handles ratings, risk vectors, findings, and portfolio companies.
Flags: low ratings (<600), critical risk vectors (botnet, open ports), declining grades.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BitSightNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "bitsight_ratings": "_normalize_ratings",
        "bitsight_risk_vectors": "_normalize_risk_vectors",
        "bitsight_findings": "_normalize_findings",
        "bitsight_portfolio": "_normalize_portfolio",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "bitsight" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all BitSight findings."""
        return {
            "raw_event_id": raw.id,
            "source": "bitsight",
            "source_type": SourceType.THIRD_PARTY_RISK,
            "provider": "bitsight",
            "observed_at": raw.observed_at,
        }

    # -- Ratings --

    def _normalize_ratings(self, raw: RawEventData) -> list[FindingData]:
        """Inventory company ratings; flag low ratings (<600)."""
        findings = []
        companies = raw.raw_data.get("companies", [])

        for company in companies:
            guid = company.get("guid", "")
            name = company.get("name", "")
            rating = company.get("rating", 0)
            rating_date = company.get("rating_date", "")
            grade = company.get("grade", "")
            grade_date = company.get("grade_date", "")
            industry = company.get("industry", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"BitSight rating: {name} ({rating})",
                    detail={
                        "guid": guid,
                        "name": name,
                        "rating": rating,
                        "rating_date": rating_date,
                        "grade": grade,
                        "grade_date": grade_date,
                        "industry": industry,
                    },
                    resource_id=guid,
                    resource_type="bitsight_company",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag low ratings
            if isinstance(rating, (int, float)) and rating < 600:
                severity = "critical" if rating < 400 else "high"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Low security rating for {name}: {rating}",
                        detail={
                            "guid": guid,
                            "name": name,
                            "rating": rating,
                            "grade": grade,
                            "issue": f"Company security rating {rating} is below acceptable threshold (600) — elevated third-party risk",
                        },
                        resource_id=guid,
                        resource_type="bitsight_company",
                        resource_name=name,
                        severity=severity,
                    )
                )

        return findings

    # -- Risk Vectors --

    def _normalize_risk_vectors(self, raw: RawEventData) -> list[FindingData]:
        """Flag critical risk vectors (botnet, open ports, patching cadence)."""
        findings = []
        vectors = raw.raw_data.get("risk_vectors", [])

        critical_vectors = {"botnet_infections", "open_ports", "patching_cadence", "spam_propagation"}

        for vector in vectors:
            vector_name = vector.get("name", "")
            vector_key = vector.get("key", "")
            grade = vector.get("grade", "")
            percentile = vector.get("percentile", 0)
            rating = vector.get("rating", 0)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"BitSight risk vector: {vector_name} (grade={grade})",
                    detail={
                        "vector_key": vector_key,
                        "vector_name": vector_name,
                        "grade": grade,
                        "percentile": percentile,
                        "rating": rating,
                    },
                    resource_id=vector_key,
                    resource_type="bitsight_risk_vector",
                    resource_name=vector_name,
                    severity="info",
                )
            )

            # Flag critical risk vectors with poor grades
            if vector_key in critical_vectors and grade in ("D", "F"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Critical risk vector failing: {vector_name} (grade={grade})",
                        detail={
                            "vector_key": vector_key,
                            "vector_name": vector_name,
                            "grade": grade,
                            "percentile": percentile,
                            "issue": f"Critical risk vector '{vector_name}' has grade {grade} — immediate remediation required",
                        },
                        resource_id=vector_key,
                        resource_type="bitsight_risk_vector",
                        resource_name=vector_name,
                        severity="critical",
                    )
                )

        return findings

    # -- Findings --

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        """Normalize BitSight security findings."""
        findings = []
        bitsight_findings = raw.raw_data.get("findings", [])

        for item in bitsight_findings:
            finding_id = item.get("id", "")
            severity_str = item.get("severity", "info")
            category = item.get("risk_category", "")
            asset = item.get("asset", "")
            first_seen = item.get("first_seen", "")
            last_seen = item.get("last_seen", "")
            details = item.get("details", {})

            sev_map = {"critical": "critical", "severe": "high", "moderate": "medium", "minor": "low"}
            severity = sev_map.get(severity_str.lower(), "info")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"BitSight finding: {category} on {asset}",
                    detail={
                        "finding_id": finding_id,
                        "category": category,
                        "asset": asset,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "details": details,
                        "original_severity": severity_str,
                    },
                    resource_id=str(finding_id),
                    resource_type="bitsight_finding",
                    resource_name=asset or str(finding_id),
                    severity=severity,
                )
            )

        return findings

    # -- Portfolio --

    def _normalize_portfolio(self, raw: RawEventData) -> list[FindingData]:
        """Inventory portfolio companies; flag those with declining grades."""
        findings = []
        companies = raw.raw_data.get("companies", [])

        for company in companies:
            guid = company.get("guid", "")
            name = company.get("name", "")
            rating = company.get("rating", 0)
            grade = company.get("grade", "")
            rating_change = company.get("rating_change", 0)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Portfolio company: {name} (rating={rating}, grade={grade})",
                    detail={
                        "guid": guid,
                        "name": name,
                        "rating": rating,
                        "grade": grade,
                        "rating_change": rating_change,
                    },
                    resource_id=guid,
                    resource_type="bitsight_portfolio_company",
                    resource_name=name,
                    severity="info",
                )
            )

            # Flag declining ratings
            if isinstance(rating_change, (int, float)) and rating_change < -50:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Declining security rating for {name}: {rating_change:+d} points",
                        detail={
                            "guid": guid,
                            "name": name,
                            "rating": rating,
                            "rating_change": rating_change,
                            "issue": f"Portfolio company rating dropped by {abs(rating_change)} points — review third-party risk posture",
                        },
                        resource_id=guid,
                        resource_type="bitsight_portfolio_company",
                        resource_name=name,
                        severity="high",
                    )
                )

        return findings


# Register
registry.register(BitSightNormalizer())
