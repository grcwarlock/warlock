"""Vendor risk monitoring and scoring engine.

Builds vendor risk profiles from SecurityScorecard connector data,
scores them on a composite 0-100 scale, and feeds results back into
the posture aggregation system for UCF-TPM controls.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlResult,
    Finding,
    SystemProfile,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Vendor:
    """Vendor metadata and assessment tracking."""

    name: str
    vendor_id: str = ""
    criticality: str = "medium"  # critical, high, medium, low
    data_sensitivity: str = "medium"  # critical, high, medium, low
    last_assessment_date: datetime | None = None
    assessment_frequency_days: int = 90  # expected reassessment cadence
    security_score: float = 0.0  # 0-100, from SecurityScorecard
    security_factors: dict[str, float] = field(default_factory=dict)
    issues: list[dict[str, Any]] = field(default_factory=list)
    sla_metrics: dict[str, Any] = field(default_factory=dict)
    finding_ids: list[str] = field(default_factory=list)


@dataclass
class VendorRiskScore:
    """Composite vendor risk score with breakdown."""

    vendor_name: str
    vendor_id: str
    overall_score: float  # 0-100, higher = lower risk
    criticality_score: float  # 0-25
    data_sensitivity_score: float  # 0-20
    assessment_currency_score: float  # 0-20
    security_posture_score: float  # 0-25
    sla_compliance_score: float  # 0-10
    risk_level: str  # critical, high, medium, low
    issues_count: int = 0
    recommendations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scoring weights and thresholds
# ---------------------------------------------------------------------------

_CRITICALITY_SCORES: dict[str, float] = {
    "critical": 5.0,  # Most critical vendors = lowest score contribution
    "high": 10.0,
    "medium": 18.0,
    "low": 25.0,
}

_SENSITIVITY_SCORES: dict[str, float] = {
    "critical": 4.0,
    "high": 8.0,
    "medium": 14.0,
    "low": 20.0,
}


def _risk_level(score: float) -> str:
    """Convert a 0-100 risk score to a risk level label."""
    if score >= 80:
        return "low"
    elif score >= 60:
        return "medium"
    elif score >= 40:
        return "high"
    else:
        return "critical"


# ---------------------------------------------------------------------------
# VendorRiskEngine
# ---------------------------------------------------------------------------


class VendorRiskEngine:
    """Weighted composite scoring engine for vendor risk assessment."""

    def __init__(
        self,
        weights: dict[str, float] | None = None,
    ) -> None:
        self.weights = weights or {
            "criticality": 1.0,
            "data_sensitivity": 1.0,
            "assessment_currency": 1.0,
            "security_posture": 1.0,
            "sla_compliance": 1.0,
        }

    def score_vendor(
        self,
        vendor: Vendor,
        sla_metrics: dict[str, Any] | None = None,
    ) -> VendorRiskScore:
        """Score a single vendor on a composite 0-100 scale.

        Scoring breakdown:
          - Criticality:          0-25 points (inverse — critical vendors score lower)
          - Data sensitivity:     0-20 points (inverse — sensitive data scores lower)
          - Assessment currency:  0-20 points (how recent the last assessment is)
          - Security posture:     0-25 points (from SecurityScorecard score)
          - SLA compliance:       0-10 points (from SLA metrics)

        Returns:
            VendorRiskScore with detailed breakdown.
        """
        criticality = self._criticality_score(vendor)
        sensitivity = self._data_sensitivity_score(vendor)
        currency = self._assessment_currency_score(vendor)
        security = self._security_posture_score(vendor)
        sla = self._sla_compliance_score(vendor, sla_metrics)

        overall = round(criticality + sensitivity + currency + security + sla, 2)

        recommendations: list[str] = []
        if currency < 10.0:
            recommendations.append(
                f"Vendor {vendor.name} assessment is overdue; schedule reassessment."
            )
        if security < 12.5:
            recommendations.append(
                f"Vendor {vendor.name} security posture is below threshold; "
                "request remediation plan."
            )
        if criticality <= 10.0 and security < 18.0:
            recommendations.append(
                f"Critical vendor {vendor.name} has weak security controls; "
                "consider risk treatment."
            )
        if sla < 5.0 and sla_metrics:
            recommendations.append(
                f"Vendor {vendor.name} is not meeting SLA commitments; review contractual terms."
            )

        return VendorRiskScore(
            vendor_name=vendor.name,
            vendor_id=vendor.vendor_id,
            overall_score=overall,
            criticality_score=round(criticality, 2),
            data_sensitivity_score=round(sensitivity, 2),
            assessment_currency_score=round(currency, 2),
            security_posture_score=round(security, 2),
            sla_compliance_score=round(sla, 2),
            risk_level=_risk_level(overall),
            issues_count=len(vendor.issues),
            recommendations=recommendations,
        )

    # --- Component scorers ---

    @staticmethod
    def _criticality_score(vendor: Vendor) -> float:
        """0-25 points: less critical vendors score higher (lower risk)."""
        return _CRITICALITY_SCORES.get(vendor.criticality.lower(), 18.0)

    @staticmethod
    def _data_sensitivity_score(vendor: Vendor) -> float:
        """0-20 points: less sensitive data access scores higher."""
        return _SENSITIVITY_SCORES.get(vendor.data_sensitivity.lower(), 14.0)

    @staticmethod
    def _assessment_currency_score(vendor: Vendor) -> float:
        """0-20 points: recent assessments score higher.

        Full marks if assessed within expected frequency; degrades linearly
        to zero at 3x the expected frequency.
        """
        if vendor.last_assessment_date is None:
            return 0.0

        now = datetime.now(timezone.utc)
        last = vendor.last_assessment_date
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        days_since = (now - last).total_seconds() / 86400
        expected = vendor.assessment_frequency_days

        if days_since <= expected:
            return 20.0
        elif days_since <= expected * 2:
            # Linear degradation from 20 to 10
            ratio = (days_since - expected) / expected
            return max(0.0, round(20.0 - 10.0 * ratio, 2))
        elif days_since <= expected * 3:
            # Linear degradation from 10 to 0
            ratio = (days_since - expected * 2) / expected
            return max(0.0, round(10.0 - 10.0 * ratio, 2))
        else:
            return 0.0

    @staticmethod
    def _security_posture_score(vendor: Vendor) -> float:
        """0-25 points: maps SecurityScorecard score (0-100) to 0-25."""
        return round(vendor.security_score * 0.25, 2)

    @staticmethod
    def _sla_compliance_score(
        vendor: Vendor,
        sla_metrics: dict[str, Any] | None = None,
    ) -> float:
        """0-10 points: based on SLA compliance metrics.

        Expected sla_metrics keys:
          - uptime_pct: float (0-100)
          - response_time_met: bool
          - breach_notification_met: bool
        """
        metrics = sla_metrics or vendor.sla_metrics
        if not metrics:
            return 5.0  # Neutral if no SLA data

        score = 0.0

        uptime = metrics.get("uptime_pct", 0.0)
        if uptime >= 99.9:
            score += 4.0
        elif uptime >= 99.0:
            score += 3.0
        elif uptime >= 95.0:
            score += 1.5
        # else 0

        if metrics.get("response_time_met", False):
            score += 3.0

        if metrics.get("breach_notification_met", False):
            score += 3.0

        return min(10.0, score)

    # --- Integration with v2 pipeline ---

    @staticmethod
    def from_findings(
        session: Session,
        provider: str = "securityscorecard",
    ) -> list[Vendor]:
        """Build Vendor objects from SecurityScorecard findings in the DB.

        Looks for Finding rows with:
          - provider matching the given provider
          - resource_type in ('vendor_company', 'vendor_risk_factor', 'vendor_issue')

        Groups findings by vendor (resource_name) and assembles Vendor objects.
        """
        findings = (
            session.query(Finding)
            .filter(
                Finding.provider == provider,
                Finding.resource_type.in_(
                    [
                        "vendor_company",
                        "vendor_risk_factor",
                        "vendor_issue",
                    ]
                ),
            )
            .order_by(Finding.observed_at.desc())
            .all()
        )

        if not findings:
            log.info("No vendor findings from provider %s", provider)
            return []

        # Group by vendor name (resource_name)
        vendor_map: dict[str, dict[str, Any]] = {}
        for f in findings:
            name = f.resource_name or f.resource_id or "unknown"
            if name not in vendor_map:
                vendor_map[name] = {
                    "name": name,
                    "vendor_id": f.resource_id or "",
                    "security_score": 0.0,
                    "factors": {},
                    "issues": [],
                    "finding_ids": [],
                    "last_observed": None,
                    "criticality": "medium",
                    "data_sensitivity": "medium",
                }

            entry = vendor_map[name]
            entry["finding_ids"].append(f.id)

            detail = f.detail or {}

            if f.resource_type == "vendor_company":
                entry["security_score"] = detail.get("overall_score", entry["security_score"])
                entry["criticality"] = detail.get("criticality", entry["criticality"])
                entry["data_sensitivity"] = detail.get(
                    "data_sensitivity", entry["data_sensitivity"]
                )
                if f.observed_at:
                    if entry["last_observed"] is None or f.observed_at > entry["last_observed"]:
                        entry["last_observed"] = f.observed_at

            elif f.resource_type == "vendor_risk_factor":
                factor_name = detail.get("factor_name", "unknown")
                factor_score = detail.get("score", 0.0)
                entry["factors"][factor_name] = factor_score

            elif f.resource_type == "vendor_issue":
                entry["issues"].append(
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "detail": detail,
                        "observed_at": f.observed_at.isoformat() if f.observed_at else None,
                    }
                )

        # Build Vendor objects
        vendors: list[Vendor] = []
        for name, data in vendor_map.items():
            vendors.append(
                Vendor(
                    name=data["name"],
                    vendor_id=data["vendor_id"],
                    criticality=data["criticality"],
                    data_sensitivity=data["data_sensitivity"],
                    last_assessment_date=data["last_observed"],
                    security_score=data["security_score"],
                    security_factors=data["factors"],
                    issues=data["issues"],
                    finding_ids=data["finding_ids"],
                )
            )

        log.info("Built %d vendor profiles from %s findings", len(vendors), provider)
        return vendors

    def monitor_all(
        self,
        session: Session,
        provider: str = "securityscorecard",
        high_risk_threshold: float = 60.0,
    ) -> list[VendorRiskScore]:
        """Score all vendors and create findings for high-risk ones.

        Vendors scoring below high_risk_threshold get a new Finding created
        with observation_type='vendor_risk_alert'.

        Returns:
            All VendorRiskScore objects.
        """
        vendors = self.from_findings(session, provider=provider)
        if not vendors:
            return []

        scores: list[VendorRiskScore] = []
        for vendor in vendors:
            score = self.score_vendor(vendor)
            scores.append(score)

            if score.overall_score < high_risk_threshold:
                log.warning(
                    "High-risk vendor: %s (score %.1f, level %s)",
                    vendor.name,
                    score.overall_score,
                    score.risk_level,
                )
                # Create a finding for the high-risk vendor so it flows
                # through the pipeline and maps to UCF-TPM controls
                _create_vendor_risk_finding(session, vendor, score)

        log.info(
            "Vendor monitoring complete: %d vendors scored, %d high-risk",
            len(scores),
            sum(1 for s in scores if s.overall_score < high_risk_threshold),
        )
        return scores


def _create_vendor_risk_finding(
    session: Session,
    vendor: Vendor,
    score: VendorRiskScore,
) -> None:
    """Create a Finding row for a high-risk vendor.

    This finding can then be picked up by the control mapper and
    mapped to UCF-TPM / SA-9 / SR-* controls.
    """
    import hashlib
    import json

    now = datetime.now(timezone.utc)
    detail = {
        "vendor_name": vendor.name,
        "vendor_id": vendor.vendor_id,
        "overall_score": score.overall_score,
        "risk_level": score.risk_level,
        "criticality": vendor.criticality,
        "data_sensitivity": vendor.data_sensitivity,
        "security_score": vendor.security_score,
        "issues_count": score.issues_count,
        "recommendations": score.recommendations,
        "breakdown": {
            "criticality": score.criticality_score,
            "data_sensitivity": score.data_sensitivity_score,
            "assessment_currency": score.assessment_currency_score,
            "security_posture": score.security_posture_score,
            "sla_compliance": score.sla_compliance_score,
        },
    }

    sha = hashlib.sha256(json.dumps(detail, sort_keys=True).encode()).hexdigest()

    # Need a raw_event_id — use the first vendor finding if available,
    # otherwise we cannot create a Finding (FK constraint).
    # In practice, vendor_risk_alert findings are synthetic; we link them
    # to the most recent raw event from this vendor's findings.
    raw_event_id = None
    if vendor.finding_ids:
        source_finding = session.query(Finding).filter(Finding.id == vendor.finding_ids[0]).first()
        if source_finding:
            raw_event_id = source_finding.raw_event_id

    if raw_event_id is None:
        log.warning(
            "Cannot create vendor risk finding for %s: no raw_event_id available",
            vendor.name,
        )
        return

    finding = Finding(
        raw_event_id=raw_event_id,
        observation_type="vendor_risk_alert",
        title=f"High-risk vendor: {vendor.name} (score {score.overall_score:.0f})",
        detail=detail,
        resource_id=vendor.vendor_id,
        resource_type="vendor_company",
        resource_name=vendor.name,
        source="warlock",
        source_type="grc",
        provider="vendor_risk_engine",
        severity=score.risk_level,
        confidence=0.9,
        observed_at=now,
        sha256=sha,
    )
    session.add(finding)
    session.flush()
    log.info("Created vendor risk finding for %s (id=%s)", vendor.name, finding.id)


# ---------------------------------------------------------------------------
# Supply chain concentration analysis
# ---------------------------------------------------------------------------


def analyze_concentration(
    session: Session,
) -> dict[str, Any]:
    """Analyze supply chain concentration risk across vendors.

    For each vendor (identified by connector_scope entries on SystemProfile),
    counts how many distinct controls depend on systems fed by that vendor's
    connector. A high concentration score means many controls rely on a
    single vendor, creating systemic risk.

    Returns:
        Dict with ``vendors`` (mapping vendor -> concentration data) and
        ``highest_concentration`` (the vendor with the most control dependencies).
    """
    profiles = session.query(SystemProfile).all()

    # Build vendor -> systems mapping from connector_scope
    vendor_systems: dict[str, list[str]] = {}
    for profile in profiles:
        scopes = profile.connector_scope or []
        for vendor in scopes:
            vendor_lower = vendor.lower()
            vendor_systems.setdefault(vendor_lower, []).append(profile.id)

    # For each vendor, count controls on its dependent systems
    vendor_data: dict[str, dict[str, Any]] = {}
    for vendor, system_ids in vendor_systems.items():
        control_count = (
            session.query(ControlResult.framework, ControlResult.control_id)
            .filter(ControlResult.system_profile_id.in_(system_ids))
            .distinct()
            .count()
        )

        vendor_data[vendor] = {
            "system_count": len(system_ids),
            "control_count": control_count,
            "system_ids": system_ids,
            "concentration_score": round(control_count / max(len(vendor_systems), 1), 2),
        }

    highest = max(
        vendor_data.items(),
        key=lambda x: x[1]["control_count"],
        default=(None, {}),
    )

    return {
        "vendors": vendor_data,
        "highest_concentration": highest[0],
        "vendor_count": len(vendor_data),
    }


def blast_radius(
    session: Session,
    vendor_name: str,
) -> dict[str, Any]:
    """Compute the blast radius if a vendor fails.

    Identifies all systems that depend on the given vendor (via
    connector_scope) and all controls assessed against those systems.

    Args:
        session: SQLAlchemy session.
        vendor_name: Vendor/connector name (e.g. "aws", "okta").

    Returns:
        Dict with ``systems`` (list of affected system profiles),
        ``controls`` (list of affected framework:control_id pairs),
        and ``control_count``.
    """
    vendor_lower = vendor_name.lower()

    profiles = session.query(SystemProfile).all()

    affected_systems: list[dict[str, Any]] = []
    affected_system_ids: list[str] = []

    for profile in profiles:
        scopes = [s.lower() for s in (profile.connector_scope or [])]
        if vendor_lower in scopes:
            affected_systems.append(
                {
                    "id": profile.id,
                    "name": profile.name,
                    "acronym": profile.acronym,
                    "frameworks": profile.frameworks or [],
                }
            )
            affected_system_ids.append(profile.id)

    affected_controls: list[dict[str, str]] = []
    if affected_system_ids:
        results = (
            session.query(
                ControlResult.framework,
                ControlResult.control_id,
                ControlResult.status,
            )
            .filter(ControlResult.system_profile_id.in_(affected_system_ids))
            .distinct()
            .all()
        )
        affected_controls = [
            {
                "framework": r.framework,
                "control_id": r.control_id,
                "status": r.status,
            }
            for r in results
        ]

    return {
        "vendor": vendor_name,
        "systems": affected_systems,
        "system_count": len(affected_systems),
        "controls": affected_controls,
        "control_count": len(affected_controls),
    }
