"""Regulatory horizon scanning for the Warlock GRC platform.

Analyzes findings and control results to detect patterns suggesting new
or evolving regulatory requirements.  Provides a hardcoded calendar of
major upcoming regulatory deadlines (DORA, NIS2, EU AI Act, SEC Cyber,
etc.) and generates advisory reports for compliance teams.

Public API::

    from warlock.ai.horizon_scanning import HorizonScanner

    scanner = HorizonScanner(session)
    changes = scanner.scan_regulatory_changes(["nist_800_53", "soc2"])
    advisory = scanner.generate_advisory(changes)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ControlResult

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class RegulatoryDeadline:
    """A known upcoming regulatory deadline or enforcement date."""

    regulation: str
    description: str
    effective_date: date
    frameworks_affected: list[str]
    impact_level: str  # critical, high, medium, low
    action_required: str


@dataclass
class EmergingRequirement:
    """A pattern detected in control results suggesting regulatory change."""

    framework: str
    pattern_type: str  # gap_cluster, failure_spike, new_control_area, coverage_decline
    description: str
    affected_controls: list[str]
    confidence: float  # 0.0-1.0
    evidence_count: int
    recommendation: str


@dataclass
class RegulatoryChange:
    """A detected or known regulatory change with impact analysis."""

    source: str  # calendar, pattern_detection, ai_analysis
    regulation: str
    description: str
    impact_level: str
    frameworks_affected: list[str]
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Advisory:
    """A compiled advisory report on upcoming regulatory changes."""

    generated_at: datetime
    deadlines: list[RegulatoryDeadline]
    emerging_requirements: list[EmergingRequirement]
    changes: list[RegulatoryChange]
    summary: str
    risk_level: str  # critical, high, medium, low


# ---------------------------------------------------------------------------
# Regulatory calendar — hardcoded major deadlines
# ---------------------------------------------------------------------------

_REGULATORY_CALENDAR: list[RegulatoryDeadline] = [
    RegulatoryDeadline(
        regulation="DORA (Digital Operational Resilience Act)",
        description="EU financial sector ICT risk management, incident reporting, and resilience testing requirements fully enforceable.",
        effective_date=date(2025, 1, 17),
        frameworks_affected=["nist_800_53", "iso_27001", "soc2"],
        impact_level="critical",
        action_required="Ensure ICT risk management framework, incident classification, and third-party oversight controls are operational.",
    ),
    RegulatoryDeadline(
        regulation="NIS2 Directive",
        description="EU Network and Information Security Directive 2 — member state transposition deadline passed; enforcement active.",
        effective_date=date(2024, 10, 17),
        frameworks_affected=["nist_800_53", "iso_27001", "nist_csf"],
        impact_level="critical",
        action_required="Verify supply chain security controls, incident reporting within 24h capability, and management accountability.",
    ),
    RegulatoryDeadline(
        regulation="EU AI Act — Prohibited Practices",
        description="Ban on unacceptable-risk AI systems (social scoring, real-time biometric ID in public spaces).",
        effective_date=date(2025, 2, 2),
        frameworks_affected=["eu_ai_act", "gdpr"],
        impact_level="critical",
        action_required="Audit all AI systems for prohibited use cases. Remove or redesign any that qualify.",
    ),
    RegulatoryDeadline(
        regulation="EU AI Act — GPAI Transparency",
        description="General-purpose AI model transparency obligations and codes of practice apply.",
        effective_date=date(2025, 8, 2),
        frameworks_affected=["eu_ai_act", "iso_42001"],
        impact_level="high",
        action_required="Document GPAI model capabilities, training data summaries, and publish technical documentation.",
    ),
    RegulatoryDeadline(
        regulation="EU AI Act — High-Risk AI Systems",
        description="Full compliance required for high-risk AI systems (Annex III) including conformity assessments.",
        effective_date=date(2026, 8, 2),
        frameworks_affected=["eu_ai_act", "iso_42001", "nist_800_53"],
        impact_level="critical",
        action_required="Complete risk management systems, data governance, human oversight, and conformity assessments for high-risk AI.",
    ),
    RegulatoryDeadline(
        regulation="SEC Cybersecurity Disclosure Rules",
        description="Annual cybersecurity risk management disclosure (Form 10-K) and material incident reporting (8-K) requirements.",
        effective_date=date(2023, 12, 18),
        frameworks_affected=["sec_cyber", "nist_csf", "soc2"],
        impact_level="high",
        action_required="Ensure 4-business-day material incident reporting capability and annual cybersecurity governance disclosures.",
    ),
    RegulatoryDeadline(
        regulation="SEC Cybersecurity — Smaller Reporting Companies",
        description="Form 8-K incident disclosure requirements extend to smaller reporting companies.",
        effective_date=date(2024, 6, 15),
        frameworks_affected=["sec_cyber", "nist_csf"],
        impact_level="high",
        action_required="Establish incident materiality determination process and 8-K filing workflows.",
    ),
    RegulatoryDeadline(
        regulation="PCI DSS v4.0 — Full Enforcement",
        description="All PCI DSS v4.0 requirements become mandatory (future-dated requirements enforced).",
        effective_date=date(2025, 3, 31),
        frameworks_affected=["pci_dss"],
        impact_level="critical",
        action_required="Implement targeted risk analysis for customized approach, authenticated vulnerability scanning, and enhanced password policies.",
    ),
    RegulatoryDeadline(
        regulation="CMMC 2.0 — Final Rule Effective",
        description="Cybersecurity Maturity Model Certification program rule effective; phased implementation in DoD contracts.",
        effective_date=date(2024, 12, 16),
        frameworks_affected=["cmmc_l2", "nist_800_53"],
        impact_level="high",
        action_required="Complete CMMC Level 2 self-assessment or schedule C3PAO assessment for applicable contracts.",
    ),
    RegulatoryDeadline(
        regulation="HIPAA Security Rule Update (Proposed)",
        description="HHS proposed updates to HIPAA Security Rule including mandatory encryption, MFA, and 72-hour restore requirements.",
        effective_date=date(2026, 6, 1),
        frameworks_affected=["hipaa", "nist_800_53"],
        impact_level="high",
        action_required="Review proposed rule; begin gap analysis for encryption-at-rest, network segmentation, and MFA requirements.",
    ),
    RegulatoryDeadline(
        regulation="NIST CSF 2.0 — Govern Function",
        description="NIST Cybersecurity Framework 2.0 adds Govern function; organizations should align risk governance practices.",
        effective_date=date(2024, 2, 26),
        frameworks_affected=["nist_csf", "nist_800_53"],
        impact_level="medium",
        action_required="Map existing governance controls to CSF 2.0 Govern function categories. Update risk management policies.",
    ),
    RegulatoryDeadline(
        regulation="ISO 27001:2022 — Transition Deadline",
        description="All ISO 27001:2013 certificates must transition to ISO 27001:2022.",
        effective_date=date(2025, 10, 31),
        frameworks_affected=["iso_27001"],
        impact_level="high",
        action_required="Complete transition audit, implement Annex A changes (threat intelligence, cloud security, data masking controls).",
    ),
]


# ---------------------------------------------------------------------------
# Pattern detection thresholds
# ---------------------------------------------------------------------------

_FAILURE_SPIKE_THRESHOLD = 0.3  # 30% failure rate triggers a spike alert
_GAP_CLUSTER_MIN_CONTROLS = 3  # Minimum controls in a gap cluster
_COVERAGE_DECLINE_THRESHOLD = 0.1  # 10% decline in coverage triggers alert


# ---------------------------------------------------------------------------
# HorizonScanner
# ---------------------------------------------------------------------------


class HorizonScanner:
    """Regulatory horizon scanning engine.

    Combines a hardcoded regulatory calendar with pattern detection
    against live control result and finding data to surface upcoming
    compliance obligations and emerging regulatory risks.

    Parameters
    ----------
    session:
        An active SQLAlchemy session for database queries.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- Public API ---------------------------------------------------------

    def scan_regulatory_changes(
        self,
        frameworks: list[str] | None = None,
    ) -> list[RegulatoryChange]:
        """Analyze findings and control results for regulatory change signals.

        Combines calendar-based deadlines with pattern detection on live
        data to produce a unified list of regulatory changes requiring
        attention.

        Parameters
        ----------
        frameworks:
            Optional list of framework identifiers to scope the scan.
            When ``None``, scans all frameworks present in the database.

        Returns
        -------
        list[RegulatoryChange]
            Detected and known regulatory changes, sorted by impact level.
        """
        changes: list[RegulatoryChange] = []

        # Calendar-based changes
        for deadline in self.get_regulatory_calendar(frameworks):
            changes.append(
                RegulatoryChange(
                    source="calendar",
                    regulation=deadline.regulation,
                    description=deadline.description,
                    impact_level=deadline.impact_level,
                    frameworks_affected=deadline.frameworks_affected,
                    details={
                        "effective_date": deadline.effective_date.isoformat(),
                        "action_required": deadline.action_required,
                    },
                )
            )

        # Pattern-based emerging requirements
        target_frameworks = frameworks or self._get_active_frameworks()
        for fw in target_frameworks:
            for req in self.detect_emerging_requirements(fw):
                changes.append(
                    RegulatoryChange(
                        source="pattern_detection",
                        regulation=f"Emerging: {req.pattern_type} in {fw}",
                        description=req.description,
                        impact_level="high" if req.confidence >= 0.7 else "medium",
                        frameworks_affected=[fw],
                        details={
                            "pattern_type": req.pattern_type,
                            "affected_controls": req.affected_controls,
                            "confidence": req.confidence,
                            "evidence_count": req.evidence_count,
                            "recommendation": req.recommendation,
                        },
                    )
                )

        # Sort by impact level priority
        priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        changes.sort(key=lambda c: priority.get(c.impact_level, 4))
        return changes

    def detect_emerging_requirements(
        self,
        framework: str,
    ) -> list[EmergingRequirement]:
        """Detect patterns in control results suggesting emerging requirements.

        Runs three pattern detectors against the specified framework:

        1. **Failure spike** -- controls with abnormally high non-compliance rates
        2. **Gap cluster** -- groups of related controls all showing gaps
        3. **Coverage decline** -- frameworks where assessed coverage is dropping

        Parameters
        ----------
        framework:
            The framework identifier to analyze.

        Returns
        -------
        list[EmergingRequirement]
            Detected patterns with confidence scores and recommendations.
        """
        requirements: list[EmergingRequirement] = []

        requirements.extend(self._detect_failure_spikes(framework))
        requirements.extend(self._detect_gap_clusters(framework))
        requirements.extend(self._detect_coverage_decline(framework))

        return requirements

    def generate_advisory(
        self,
        changes: list[RegulatoryChange],
    ) -> Advisory:
        """Generate an advisory report from detected regulatory changes.

        Compiles changes into a structured advisory with a human-readable
        summary and overall risk level assessment.

        Parameters
        ----------
        changes:
            List of regulatory changes (from ``scan_regulatory_changes``).

        Returns
        -------
        Advisory
            Compiled advisory report.
        """
        now = datetime.now(timezone.utc)

        # Separate calendar deadlines from detected patterns
        deadlines = [
            d
            for d in _REGULATORY_CALENDAR
            if any(c.source == "calendar" and c.regulation == d.regulation for c in changes)
        ]

        emerging = [
            EmergingRequirement(
                framework=c.frameworks_affected[0] if c.frameworks_affected else "unknown",
                pattern_type=c.details.get("pattern_type", "unknown"),
                description=c.description,
                affected_controls=c.details.get("affected_controls", []),
                confidence=c.details.get("confidence", 0.5),
                evidence_count=c.details.get("evidence_count", 0),
                recommendation=c.details.get("recommendation", ""),
            )
            for c in changes
            if c.source == "pattern_detection"
        ]

        # Determine overall risk level
        impact_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for c in changes:
            impact_counts[c.impact_level] = impact_counts.get(c.impact_level, 0) + 1

        if impact_counts["critical"] > 0:
            risk_level = "critical"
        elif impact_counts["high"] > 0:
            risk_level = "high"
        elif impact_counts["medium"] > 0:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Build summary
        parts: list[str] = []
        total = len(changes)
        parts.append(f"{total} regulatory change(s) detected.")
        if impact_counts["critical"]:
            parts.append(
                f"{impact_counts['critical']} critical-impact item(s) require immediate attention."
            )
        if impact_counts["high"]:
            parts.append(
                f"{impact_counts['high']} high-impact item(s) should be addressed within 30 days."
            )
        if emerging:
            parts.append(
                f"{len(emerging)} emerging pattern(s) detected in control results that may indicate "
                "evolving regulatory expectations."
            )
        if not changes:
            parts = ["No regulatory changes detected for the scoped frameworks."]

        summary = " ".join(parts)

        return Advisory(
            generated_at=now,
            deadlines=deadlines,
            emerging_requirements=emerging,
            changes=changes,
            summary=summary,
            risk_level=risk_level,
        )

    def get_regulatory_calendar(
        self,
        frameworks: list[str] | None = None,
    ) -> list[RegulatoryDeadline]:
        """Return known upcoming regulatory deadlines.

        Returns a hardcoded calendar of major regulations with their
        effective dates, affected frameworks, and required actions.

        Parameters
        ----------
        frameworks:
            Optional filter to return only deadlines affecting these
            frameworks.  When ``None``, returns the full calendar.

        Returns
        -------
        list[RegulatoryDeadline]
            Deadlines sorted by effective date (earliest first).
        """
        if frameworks is None:
            result = list(_REGULATORY_CALENDAR)
        else:
            fw_set = set(frameworks)
            result = [d for d in _REGULATORY_CALENDAR if fw_set & set(d.frameworks_affected)]

        result.sort(key=lambda d: d.effective_date)
        return result

    # -- Internal pattern detectors -----------------------------------------

    def _get_active_frameworks(self) -> list[str]:
        """Return distinct framework identifiers from the database."""
        rows = self._session.query(ControlResult.framework).distinct().limit(50).all()
        return [r.framework for r in rows]

    def _detect_failure_spikes(self, framework: str) -> list[EmergingRequirement]:
        """Detect controls with abnormally high failure rates."""
        rows = (
            self._session.query(
                ControlResult.control_id,
                func.count(ControlResult.id).label("total"),
                func.sum(
                    (ControlResult.status == "non_compliant").cast(int)  # type: ignore[arg-type]
                ).label("failures"),
            )
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.control_id)
            .having(func.count(ControlResult.id) >= 5)  # Minimum sample size
            .all()
        )

        requirements: list[EmergingRequirement] = []
        high_failure_controls: list[str] = []

        for r in rows:
            total = int(r.total or 0)
            failures = int(r.failures or 0)
            if total == 0:
                continue
            rate = failures / total
            if rate >= _FAILURE_SPIKE_THRESHOLD:
                high_failure_controls.append(r.control_id)

        if high_failure_controls:
            confidence = min(1.0, len(high_failure_controls) / 10.0)
            requirements.append(
                EmergingRequirement(
                    framework=framework,
                    pattern_type="failure_spike",
                    description=(
                        f"{len(high_failure_controls)} control(s) in {framework} show "
                        f"non-compliance rates above {_FAILURE_SPIKE_THRESHOLD:.0%}. "
                        "This may indicate tightening regulatory expectations or "
                        "infrastructure drift requiring updated controls."
                    ),
                    affected_controls=high_failure_controls[:20],
                    confidence=confidence,
                    evidence_count=sum(int(r.total or 0) for r in rows),
                    recommendation=(
                        "Review the failing controls for recent regulatory guidance updates. "
                        "Prioritize remediation of controls with the highest failure rates."
                    ),
                )
            )

        return requirements

    def _detect_gap_clusters(self, framework: str) -> list[EmergingRequirement]:
        """Detect clusters of related controls all showing assessment gaps."""
        rows = (
            self._session.query(
                ControlResult.control_id,
                func.count(ControlResult.id).label("total"),
                func.sum(
                    (ControlResult.status == "not_assessed").cast(int)  # type: ignore[arg-type]
                ).label("not_assessed"),
            )
            .filter(ControlResult.framework == framework)
            .group_by(ControlResult.control_id)
            .all()
        )

        requirements: list[EmergingRequirement] = []
        gap_controls: list[str] = []

        for r in rows:
            total = int(r.total or 0)
            not_assessed = int(r.not_assessed or 0)
            if total > 0 and not_assessed / total > 0.5:
                gap_controls.append(r.control_id)

        if len(gap_controls) >= _GAP_CLUSTER_MIN_CONTROLS:
            # Group by control family prefix (e.g., AC-*, SC-*)
            families: dict[str, list[str]] = {}
            for ctrl in gap_controls:
                prefix = ctrl.split("-")[0] if "-" in ctrl else ctrl.split(".")[0]
                families.setdefault(prefix, []).append(ctrl)

            for family, controls in families.items():
                if len(controls) >= _GAP_CLUSTER_MIN_CONTROLS:
                    requirements.append(
                        EmergingRequirement(
                            framework=framework,
                            pattern_type="gap_cluster",
                            description=(
                                f"Control family '{family}' in {framework} has "
                                f"{len(controls)} control(s) with >50% unassessed results. "
                                "This gap cluster suggests a systemic coverage deficiency "
                                "that may be flagged in upcoming audits."
                            ),
                            affected_controls=controls[:20],
                            confidence=min(1.0, len(controls) / 10.0),
                            evidence_count=len(controls),
                            recommendation=(
                                f"Expand assessment coverage for the {family} control family. "
                                "Add connectors or data sources that provide evidence for these controls."
                            ),
                        )
                    )

        return requirements

    def _detect_coverage_decline(self, framework: str) -> list[EmergingRequirement]:
        """Detect frameworks where assessed coverage is declining."""
        total_results = (
            self._session.query(func.count(ControlResult.id))
            .filter(ControlResult.framework == framework)
            .scalar()
        ) or 0

        if total_results == 0:
            return []

        not_assessed = (
            self._session.query(func.count(ControlResult.id))
            .filter(
                ControlResult.framework == framework,
                ControlResult.status == "not_assessed",
            )
            .scalar()
        ) or 0

        not_assessed_rate = not_assessed / total_results if total_results else 0.0

        requirements: list[EmergingRequirement] = []
        if not_assessed_rate > _COVERAGE_DECLINE_THRESHOLD:
            requirements.append(
                EmergingRequirement(
                    framework=framework,
                    pattern_type="coverage_decline",
                    description=(
                        f"{framework} has {not_assessed_rate:.0%} of control results "
                        "in 'not_assessed' status. Coverage may be declining due to "
                        "new controls being added by the framework without corresponding "
                        "evidence sources."
                    ),
                    affected_controls=[],
                    confidence=min(1.0, not_assessed_rate * 2),
                    evidence_count=total_results,
                    recommendation=(
                        f"Review {framework} control catalog for recently added requirements. "
                        "Map new controls to existing data sources or onboard new connectors."
                    ),
                )
            )

        return requirements
