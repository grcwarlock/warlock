"""Auditor workflow — structured evidence packaging for audit engagements.

Builds the evidence packages auditors actually need: per-control artifact
bundles with integrity hashes, gap analysis, and export to structured JSON.

Builds on top of the temporal packager's raw evidence queries, adding
auditor-specific structure (artifact typing, hash chains, gap detection).
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import distinct
from sqlalchemy.orm import Session

from warlock.db.models import (
    AuditEngagement,
    ControlMapping,
    ControlResult,
    Finding,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _sha256(data: Any) -> str:
    """SHA-256 hex digest of a JSON-serialised payload."""
    raw = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass
class EvidenceArtifact:
    """A single piece of evidence for an auditor."""

    artifact_id: str
    control_id: str
    framework: str
    title: str
    description: str
    source: str  # provider name
    collected_at: datetime
    artifact_type: str  # automated_test, configuration, log_entry, policy_document
    status: str  # pass, fail, informational
    raw_data_hash: str  # SHA256 for integrity
    data: dict  # the actual evidence payload


@dataclass
class ControlEvidencePackage:
    """All evidence for a single control, structured for auditor review."""

    framework: str
    control_id: str
    control_family: str
    overall_status: str  # compliant, non_compliant, partial
    artifacts: list[EvidenceArtifact] = field(default_factory=list)
    assertions_run: list[dict] = field(default_factory=list)  # assertion name, passed, findings
    gaps: list[str] = field(default_factory=list)  # what evidence is missing
    recommendations: list[str] = field(default_factory=list)


@dataclass
class AuditPackage:
    """Complete evidence package for an audit engagement."""

    engagement_id: str
    framework: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime = field(default_factory=_utcnow)
    control_packages: dict[str, ControlEvidencePackage] = field(default_factory=dict)
    summary: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_to_artifact(
    finding: Finding,
    control_id: str,
    framework: str,
) -> EvidenceArtifact:
    """Convert a Finding row into an EvidenceArtifact."""
    # Determine artifact type from observation_type
    type_map = {
        "misconfiguration": "configuration",
        "vulnerability": "automated_test",
        "alert": "log_entry",
        "policy_violation": "automated_test",
        "access_anomaly": "log_entry",
        "inventory": "configuration",
    }
    artifact_type = type_map.get(finding.observation_type, "log_entry")

    # Determine status from severity
    status_map = {"critical": "fail", "high": "fail", "medium": "fail", "low": "informational", "info": "informational"}
    status = status_map.get(finding.severity, "informational")

    data_payload = {
        "finding_id": finding.id,
        "title": finding.title,
        "observation_type": finding.observation_type,
        "detail": finding.detail,
        "resource_id": finding.resource_id or "",
        "resource_type": finding.resource_type or "",
        "resource_name": finding.resource_name or "",
        "account_id": finding.account_id or "",
        "region": finding.region or "",
        "severity": finding.severity,
        "confidence": finding.confidence,
    }

    return EvidenceArtifact(
        artifact_id=finding.id,
        control_id=control_id,
        framework=framework,
        title=finding.title,
        description=f"{finding.observation_type}: {finding.title}",
        source=finding.provider,
        collected_at=finding.observed_at or finding.ingested_at,
        artifact_type=artifact_type,
        status=status,
        raw_data_hash=finding.sha256,
        data=data_payload,
    )


def _result_to_assertion_record(result: ControlResult) -> dict:
    """Summarise a ControlResult as an assertion record."""
    return {
        "result_id": result.id,
        "assertion_name": result.assertion_name or "",
        "passed": result.assertion_passed,
        "status": result.status,
        "assessor": result.assessor,
        "assessed_at": _iso(result.assessed_at),
        "findings": result.assertion_findings or [],
    }


def _determine_overall_status(results: list[ControlResult]) -> str:
    """Derive overall control status from its result set."""
    if not results:
        return "non_compliant"  # no evidence = non-compliant

    statuses = {r.status for r in results}
    if statuses == {"compliant"}:
        return "compliant"
    if "non_compliant" in statuses:
        return "non_compliant"
    if "partial" in statuses or ("compliant" in statuses and len(statuses) > 1):
        return "partial"
    return "non_compliant"


# ---------------------------------------------------------------------------
# AuditorWorkflow
# ---------------------------------------------------------------------------


class AuditorWorkflow:
    """Builds structured evidence packages for auditors."""

    def build_control_package(
        self,
        session: Session,
        framework: str,
        control_id: str,
        start: datetime,
        end: datetime,
    ) -> ControlEvidencePackage:
        """Build evidence package for a single control within a date range.

        Queries all findings and results for this control in the period,
        builds EvidenceArtifacts, and computes gaps.
        """
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        # Fetch results for this control in the period
        results: list[ControlResult] = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.control_id == control_id,
                ControlResult.assessed_at >= start,
                ControlResult.assessed_at <= end,
            )
            .order_by(ControlResult.assessed_at.desc())
            .all()
        )

        # Fetch findings via control mappings
        mappings = (
            session.query(ControlMapping)
            .filter(
                ControlMapping.framework == framework,
                ControlMapping.control_id == control_id,
            )
            .all()
        )
        finding_ids = {m.finding_id for m in mappings}
        # Also include findings referenced by results
        finding_ids.update(r.finding_id for r in results)

        findings: list[Finding] = []
        if finding_ids:
            findings = (
                session.query(Finding)
                .filter(
                    Finding.id.in_(finding_ids),
                    Finding.observed_at >= start,
                    Finding.observed_at <= end,
                )
                .order_by(Finding.observed_at.desc())
                .all()
            )

        # Determine control family from the first mapping
        control_family = ""
        if mappings:
            control_family = mappings[0].control_family or ""

        # Build artifacts from findings
        artifacts = [
            _finding_to_artifact(f, control_id, framework) for f in findings
        ]

        # Build assertion records from results
        assertions_run = [_result_to_assertion_record(r) for r in results]

        # Determine overall status
        overall_status = _determine_overall_status(results)

        # Compute gaps
        gaps: list[str] = []
        if not findings:
            gaps.append(f"No evidence collected for {control_id} in the audit period")
        if not results:
            gaps.append(f"No assessments run for {control_id} in the audit period")
        elif all(r.assessor == "none" for r in results):
            gaps.append(f"No assertions defined for {control_id}")

        # Recommendations based on gaps/status
        recommendations: list[str] = []
        if overall_status == "non_compliant":
            recommendations.append(
                f"Remediate non-compliant findings for {control_id} before audit"
            )
        if not findings:
            recommendations.append(
                f"Configure a connector to collect evidence for {control_id}"
            )

        return ControlEvidencePackage(
            framework=framework,
            control_id=control_id,
            control_family=control_family,
            overall_status=overall_status,
            artifacts=artifacts,
            assertions_run=assertions_run,
            gaps=gaps,
            recommendations=recommendations,
        )

    def build_audit_package(
        self,
        session: Session,
        engagement_id: str,
    ) -> AuditPackage:
        """Build complete audit package for an engagement.

        Loads the AuditEngagement record to determine framework, date range,
        and scope, then builds a ControlEvidencePackage for each in-scope control.
        """
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id == engagement_id)
            .first()
        )
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        framework = eng.framework
        start = eng.period_start
        end = eng.period_end

        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        # Determine in-scope controls
        if eng.in_scope_controls:
            control_ids = list(eng.in_scope_controls)
            if eng.excluded_controls:
                excluded = set(eng.excluded_controls)
                control_ids = [c for c in control_ids if c not in excluded]
        else:
            # All controls in the framework
            rows = (
                session.query(distinct(ControlMapping.control_id))
                .filter(ControlMapping.framework == framework)
                .all()
            )
            control_ids = [row[0] for row in rows]
            if eng.excluded_controls:
                excluded = set(eng.excluded_controls)
                control_ids = [c for c in control_ids if c not in excluded]

        # Pre-load all data for the framework/date range in 3 bulk queries
        # to avoid N+1 queries in the per-control loop below.
        all_results: list[ControlResult] = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.assessed_at >= start,
                ControlResult.assessed_at <= end,
            )
            .order_by(ControlResult.assessed_at.desc())
            .all()
        )
        results_by_control: dict[str, list[ControlResult]] = {}
        for r in all_results:
            results_by_control.setdefault(r.control_id, []).append(r)

        all_mappings: list[ControlMapping] = (
            session.query(ControlMapping)
            .filter(ControlMapping.framework == framework)
            .all()
        )
        mappings_by_control: dict[str, list[ControlMapping]] = {}
        for m in all_mappings:
            mappings_by_control.setdefault(m.control_id, []).append(m)

        # Collect all finding IDs referenced by mappings and results
        all_finding_ids: set[str] = set()
        for m in all_mappings:
            all_finding_ids.add(m.finding_id)
        for r in all_results:
            all_finding_ids.add(r.finding_id)

        all_findings_list: list[Finding] = []
        if all_finding_ids:
            all_findings_list = (
                session.query(Finding)
                .filter(
                    Finding.id.in_(all_finding_ids),
                    Finding.observed_at >= start,
                    Finding.observed_at <= end,
                )
                .order_by(Finding.observed_at.desc())
                .all()
            )
        findings_by_id: dict[str, Finding] = {f.id: f for f in all_findings_list}

        # Build per-control packages using in-memory data (no per-control DB hits)
        control_packages: dict[str, ControlEvidencePackage] = {}
        for cid in sorted(control_ids):
            control_packages[cid] = self._build_control_package_from_cache(
                framework,
                cid,
                results_by_control.get(cid, []),
                mappings_by_control.get(cid, []),
                findings_by_id,
            )

        # Compute summary
        total = len(control_packages)
        compliant = sum(
            1 for p in control_packages.values() if p.overall_status == "compliant"
        )
        non_compliant = sum(
            1 for p in control_packages.values() if p.overall_status == "non_compliant"
        )
        partial = sum(
            1 for p in control_packages.values() if p.overall_status == "partial"
        )
        all_gaps = []
        for p in control_packages.values():
            all_gaps.extend(p.gaps)

        summary = {
            "total_controls": total,
            "controls_tested": total - non_compliant,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "pass_rate": round(compliant / total * 100, 2) if total > 0 else 0.0,
            "total_gaps": len(all_gaps),
        }

        return AuditPackage(
            engagement_id=engagement_id,
            framework=framework,
            period_start=start,
            period_end=end,
            control_packages=control_packages,
            summary=summary,
        )

    def _build_control_package_from_cache(
        self,
        framework: str,
        control_id: str,
        results: list[ControlResult],
        mappings: list[ControlMapping],
        findings_by_id: dict[str, "Finding"],
    ) -> ControlEvidencePackage:
        """Build a ControlEvidencePackage from pre-fetched, in-memory data.

        Called by build_audit_package to avoid per-control DB queries (N+1).
        """
        # Collect finding IDs for this control
        finding_ids: set[str] = {m.finding_id for m in mappings}
        finding_ids.update(r.finding_id for r in results)

        findings = [findings_by_id[fid] for fid in finding_ids if fid in findings_by_id]

        control_family = ""
        if mappings:
            control_family = mappings[0].control_family or ""

        artifacts = [_finding_to_artifact(f, control_id, framework) for f in findings]
        assertions_run = [_result_to_assertion_record(r) for r in results]
        overall_status = _determine_overall_status(results)

        gaps: list[str] = []
        if not findings:
            gaps.append(f"No evidence collected for {control_id} in the audit period")
        if not results:
            gaps.append(f"No assessments run for {control_id} in the audit period")
        elif all(r.assessor == "none" for r in results):
            gaps.append(f"No assertions defined for {control_id}")

        recommendations: list[str] = []
        if overall_status == "non_compliant":
            recommendations.append(
                f"Remediate non-compliant findings for {control_id} before audit"
            )
        if not findings:
            recommendations.append(
                f"Configure a connector to collect evidence for {control_id}"
            )

        return ControlEvidencePackage(
            framework=framework,
            control_id=control_id,
            control_family=control_family,
            overall_status=overall_status,
            artifacts=artifacts,
            assertions_run=assertions_run,
            gaps=gaps,
            recommendations=recommendations,
        )

    def export_package_json(self, package: AuditPackage) -> str:
        """Export audit package as structured JSON."""

        def _serialize(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return _iso(obj)
            if isinstance(obj, EvidenceArtifact):
                return {
                    "artifact_id": obj.artifact_id,
                    "control_id": obj.control_id,
                    "framework": obj.framework,
                    "title": obj.title,
                    "description": obj.description,
                    "source": obj.source,
                    "collected_at": _iso(obj.collected_at),
                    "artifact_type": obj.artifact_type,
                    "status": obj.status,
                    "raw_data_hash": obj.raw_data_hash,
                    "data": obj.data,
                }
            if isinstance(obj, ControlEvidencePackage):
                return {
                    "framework": obj.framework,
                    "control_id": obj.control_id,
                    "control_family": obj.control_family,
                    "overall_status": obj.overall_status,
                    "artifacts": [_serialize(a) for a in obj.artifacts],
                    "assertions_run": obj.assertions_run,
                    "gaps": obj.gaps,
                    "recommendations": obj.recommendations,
                }
            return str(obj)

        data = {
            "engagement_id": package.engagement_id,
            "framework": package.framework,
            "period_start": _iso(package.period_start),
            "period_end": _iso(package.period_end),
            "generated_at": _iso(package.generated_at),
            "summary": package.summary,
            "control_packages": {
                cid: _serialize(cp)
                for cid, cp in package.control_packages.items()
            },
        }
        return json.dumps(data, indent=2, default=_serialize)

    def export_package_for_framework(
        self,
        session: Session,
        framework: str,
        start: datetime,
        end: datetime,
    ) -> AuditPackage:
        """Build a package for a framework without an engagement record.

        Convenience method for ad-hoc evidence packaging.
        """
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        # All controls in the framework
        rows = (
            session.query(distinct(ControlMapping.control_id))
            .filter(ControlMapping.framework == framework)
            .all()
        )
        control_ids = sorted(row[0] for row in rows)

        # Pre-load all data in 3 bulk queries to avoid N+1
        all_results: list[ControlResult] = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.assessed_at >= start,
                ControlResult.assessed_at <= end,
            )
            .order_by(ControlResult.assessed_at.desc())
            .all()
        )
        results_by_control: dict[str, list[ControlResult]] = {}
        for r in all_results:
            results_by_control.setdefault(r.control_id, []).append(r)

        all_mappings: list[ControlMapping] = (
            session.query(ControlMapping)
            .filter(ControlMapping.framework == framework)
            .all()
        )
        mappings_by_control: dict[str, list[ControlMapping]] = {}
        for m in all_mappings:
            mappings_by_control.setdefault(m.control_id, []).append(m)

        all_finding_ids: set[str] = set()
        for m in all_mappings:
            all_finding_ids.add(m.finding_id)
        for r in all_results:
            all_finding_ids.add(r.finding_id)

        all_findings_list: list[Finding] = []
        if all_finding_ids:
            all_findings_list = (
                session.query(Finding)
                .filter(
                    Finding.id.in_(all_finding_ids),
                    Finding.observed_at >= start,
                    Finding.observed_at <= end,
                )
                .order_by(Finding.observed_at.desc())
                .all()
            )
        findings_by_id: dict[str, Finding] = {f.id: f for f in all_findings_list}

        control_packages: dict[str, ControlEvidencePackage] = {}
        for cid in control_ids:
            control_packages[cid] = self._build_control_package_from_cache(
                framework,
                cid,
                results_by_control.get(cid, []),
                mappings_by_control.get(cid, []),
                findings_by_id,
            )

        total = len(control_packages)
        compliant = sum(
            1 for p in control_packages.values() if p.overall_status == "compliant"
        )
        non_compliant = sum(
            1 for p in control_packages.values() if p.overall_status == "non_compliant"
        )
        partial = sum(
            1 for p in control_packages.values() if p.overall_status == "partial"
        )

        summary = {
            "total_controls": total,
            "controls_tested": total - non_compliant,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "pass_rate": round(compliant / total * 100, 2) if total > 0 else 0.0,
        }

        return AuditPackage(
            engagement_id="adhoc",
            framework=framework,
            period_start=start,
            period_end=end,
            control_packages=control_packages,
            summary=summary,
        )
