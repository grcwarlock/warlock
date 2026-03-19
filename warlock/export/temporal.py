"""Temporal evidence packaging for audit periods.

Generates evidence packages scoped to specific time ranges,
answering: "give me all evidence for SOC 2 Type II covering Jan 1 - Dec 31 2025"
"""

from __future__ import annotations

import csv
import io
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

@dataclass
class ControlEvidence:
    """Evidence collected for a single control within a time period."""
    control_id: str
    framework: str
    finding_count: int
    result_count: int
    statuses: dict[str, int]  # {"compliant": 10, "non_compliant": 2}
    sources: list[str]
    earliest_evidence: datetime | None
    latest_evidence: datetime | None
    findings: list[dict[str, Any]]  # summarized finding data
    results: list[dict[str, Any]]  # summarized result data


@dataclass
class EvidencePackage:
    """Complete evidence package for a framework within a time period."""
    framework: str
    period_start: datetime
    period_end: datetime
    controls_in_scope: int
    controls_with_evidence: int
    controls_without_evidence: int
    total_findings: int
    total_results: int
    evidence_by_control: dict[str, ControlEvidence]  # control_id -> evidence
    gaps: list[str]  # controls with no evidence in period
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt: datetime | None) -> str:
    """Datetime to ISO-8601 string."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _summarize_finding(finding: Finding) -> dict[str, Any]:
    """Build a summary dict from a Finding row."""
    return {
        "id": finding.id,
        "title": finding.title,
        "observation_type": finding.observation_type,
        "resource_id": finding.resource_id or "",
        "resource_type": finding.resource_type or "",
        "resource_name": finding.resource_name or "",
        "account_id": finding.account_id or "",
        "region": finding.region or "",
        "source": finding.source,
        "source_type": finding.source_type,
        "provider": finding.provider,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "observed_at": _iso(finding.observed_at),
        "ingested_at": _iso(finding.ingested_at),
    }


def _summarize_result(result: ControlResult) -> dict[str, Any]:
    """Build a summary dict from a ControlResult row."""
    return {
        "id": result.id,
        "finding_id": result.finding_id,
        "framework": result.framework,
        "control_id": result.control_id,
        "status": result.status,
        "severity": result.severity,
        "assertion_name": result.assertion_name or "",
        "assertion_passed": result.assertion_passed,
        "ai_assessment": (
            result.ai_assessment[:200] if result.ai_assessment else ""
        ),
        "ai_confidence": result.ai_confidence,
        "assessor": result.assessor or "",
        "assessed_at": _iso(result.assessed_at),
        "remediation_summary": result.remediation_summary or "",
    }


# ---------------------------------------------------------------------------
# TemporalPackager
# ---------------------------------------------------------------------------

class TemporalPackager:
    """Packages evidence scoped to specific time ranges."""

    def package_evidence(
        self,
        session: Session,
        framework: str,
        start: datetime,
        end: datetime,
        controls: list[str] | None = None,
    ) -> EvidencePackage:
        """Query all findings and results within date range for a framework.

        Args:
            session: SQLAlchemy session.
            framework: Framework identifier (e.g. "soc2", "nist_800_53").
            start: Period start (inclusive).
            end: Period end (inclusive).
            controls: Optional list of control IDs to scope to.

        Returns:
            EvidencePackage with all evidence organized by control.
        """
        # Ensure timezone awareness
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        # Query all ControlResults in period for this framework
        results_query = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.assessed_at >= start,
                ControlResult.assessed_at <= end,
            )
        )
        if controls:
            results_query = results_query.filter(
                ControlResult.control_id.in_(controls)
            )

        results: list[ControlResult] = results_query.all()

        # Group results by control
        results_by_control: dict[str, list[ControlResult]] = {}
        for r in results:
            results_by_control.setdefault(r.control_id, []).append(r)

        # Bulk fetch related findings
        finding_ids = {r.finding_id for r in results}
        findings_map: dict[str, Finding] = {}
        if finding_ids:
            for f in session.query(Finding).filter(Finding.id.in_(finding_ids)).all():
                findings_map[f.id] = f

        # Also get findings directly in this period for this framework
        # (via ControlMapping) that might not have results yet
        mapping_query = (
            session.query(ControlMapping)
            .filter(ControlMapping.framework == framework)
        )
        if controls:
            mapping_query = mapping_query.filter(
                ControlMapping.control_id.in_(controls)
            )
        mappings = mapping_query.all()
        mapping_finding_ids = {m.finding_id for m in mappings}

        # Fetch additional findings in period that we haven't already loaded
        additional_ids = mapping_finding_ids - finding_ids
        if additional_ids:
            additional_findings = (
                session.query(Finding)
                .filter(
                    Finding.id.in_(additional_ids),
                    Finding.observed_at >= start,
                    Finding.observed_at <= end,
                )
                .all()
            )
            for f in additional_findings:
                findings_map[f.id] = f

        # Map additional findings to controls
        findings_by_control: dict[str, list[Finding]] = {}
        for m in mappings:
            f = findings_map.get(m.finding_id)
            if f and f.observed_at:
                obs = f.observed_at
                if obs.tzinfo is None:
                    obs = obs.replace(tzinfo=timezone.utc)
                if start <= obs <= end:
                    findings_by_control.setdefault(m.control_id, []).append(f)

        # Determine all controls in scope
        all_control_ids: set[str] = set()
        if controls:
            all_control_ids = set(controls)
        else:
            # All controls that have mappings for this framework
            all_ctrl_rows = (
                session.query(distinct(ControlMapping.control_id))
                .filter(ControlMapping.framework == framework)
                .all()
            )
            all_control_ids = {row[0] for row in all_ctrl_rows}
            # Also include controls from results
            all_control_ids.update(results_by_control.keys())

        # Build per-control evidence
        evidence_by_control: dict[str, ControlEvidence] = {}
        controls_with_evidence = 0
        controls_without_evidence = 0
        total_findings = 0
        total_results = 0
        gaps: list[str] = []

        for control_id in sorted(all_control_ids):
            ctrl_results = results_by_control.get(control_id, [])
            ctrl_findings_list = findings_by_control.get(control_id, [])

            # Deduplicate findings
            seen_finding_ids: set[str] = set()
            unique_findings: list[Finding] = []
            for f in ctrl_findings_list:
                if f.id not in seen_finding_ids:
                    seen_finding_ids.add(f.id)
                    unique_findings.append(f)
            # Also add findings from results
            for r in ctrl_results:
                f = findings_map.get(r.finding_id)
                if f and f.id not in seen_finding_ids:
                    seen_finding_ids.add(f.id)
                    unique_findings.append(f)

            if not ctrl_results and not unique_findings:
                controls_without_evidence += 1
                gaps.append(control_id)
                continue

            controls_with_evidence += 1

            # Status counts
            statuses: dict[str, int] = {}
            for r in ctrl_results:
                statuses[r.status] = statuses.get(r.status, 0) + 1

            # Sources
            sources = sorted(set(
                f.provider for f in unique_findings if f.provider
            ))

            # Time range
            timestamps: list[datetime] = []
            for f in unique_findings:
                if f.observed_at:
                    ts = f.observed_at
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    timestamps.append(ts)
            for r in ctrl_results:
                if r.assessed_at:
                    ts = r.assessed_at
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    timestamps.append(ts)

            earliest = min(timestamps) if timestamps else None
            latest = max(timestamps) if timestamps else None

            finding_count = len(unique_findings)
            result_count = len(ctrl_results)
            total_findings += finding_count
            total_results += result_count

            evidence_by_control[control_id] = ControlEvidence(
                control_id=control_id,
                framework=framework,
                finding_count=finding_count,
                result_count=result_count,
                statuses=statuses,
                sources=sources,
                earliest_evidence=earliest,
                latest_evidence=latest,
                findings=[_summarize_finding(f) for f in unique_findings],
                results=[_summarize_result(r) for r in ctrl_results],
            )

        return EvidencePackage(
            framework=framework,
            period_start=start,
            period_end=end,
            controls_in_scope=len(all_control_ids),
            controls_with_evidence=controls_with_evidence,
            controls_without_evidence=controls_without_evidence,
            total_findings=total_findings,
            total_results=total_results,
            evidence_by_control=evidence_by_control,
            gaps=gaps,
        )

    def package_for_engagement(
        self,
        session: Session,
        engagement_id: str,
    ) -> EvidencePackage:
        """Package evidence using an AuditEngagement's dates and scope.

        Args:
            session: SQLAlchemy session.
            engagement_id: ID of the AuditEngagement.

        Returns:
            EvidencePackage scoped to the engagement.

        Raises:
            ValueError: If engagement not found.
        """
        eng = (
            session.query(AuditEngagement)
            .filter(AuditEngagement.id == engagement_id)
            .first()
        )
        if not eng:
            raise ValueError(f"Engagement not found: {engagement_id}")

        # Determine controls in scope
        controls: list[str] | None = None
        if eng.in_scope_controls:
            controls = list(eng.in_scope_controls)
            # Remove excluded
            if eng.excluded_controls:
                excluded = set(eng.excluded_controls)
                controls = [c for c in controls if c not in excluded]
        elif eng.excluded_controls:
            # Need to get all controls and remove excluded
            all_ctrl_rows = (
                session.query(distinct(ControlMapping.control_id))
                .filter(ControlMapping.framework == eng.framework)
                .all()
            )
            excluded = set(eng.excluded_controls)
            controls = [row[0] for row in all_ctrl_rows if row[0] not in excluded]

        return self.package_evidence(
            session=session,
            framework=eng.framework,
            start=eng.period_start,
            end=eng.period_end,
            controls=controls,
        )

    def export_package_json(self, package: EvidencePackage) -> str:
        """Serialize an EvidencePackage to JSON.

        Args:
            package: The evidence package to serialize.

        Returns:
            JSON string.
        """

        def _serialize(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return _iso(obj)
            if isinstance(obj, ControlEvidence):
                return {
                    "control_id": obj.control_id,
                    "framework": obj.framework,
                    "finding_count": obj.finding_count,
                    "result_count": obj.result_count,
                    "statuses": obj.statuses,
                    "sources": obj.sources,
                    "earliest_evidence": _iso(obj.earliest_evidence),
                    "latest_evidence": _iso(obj.latest_evidence),
                    "findings": obj.findings,
                    "results": obj.results,
                }
            return str(obj)

        data = {
            "framework": package.framework,
            "period_start": _iso(package.period_start),
            "period_end": _iso(package.period_end),
            "controls_in_scope": package.controls_in_scope,
            "controls_with_evidence": package.controls_with_evidence,
            "controls_without_evidence": package.controls_without_evidence,
            "total_findings": package.total_findings,
            "total_results": package.total_results,
            "gaps": package.gaps,
            "generated_at": _iso(package.generated_at),
            "evidence_by_control": {
                cid: _serialize(ev)
                for cid, ev in package.evidence_by_control.items()
            },
        }
        return json.dumps(data, indent=2, default=_serialize)

    def export_package_csv(self, package: EvidencePackage) -> str:
        """Export an EvidencePackage as CSV with one row per finding.

        Args:
            package: The evidence package to export.

        Returns:
            CSV string.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "framework",
            "control_id",
            "finding_id",
            "title",
            "observation_type",
            "resource_id",
            "resource_type",
            "resource_name",
            "account_id",
            "region",
            "source",
            "source_type",
            "provider",
            "severity",
            "confidence",
            "observed_at",
            "ingested_at",
            "assessment_status",
            "assertion_name",
            "assertion_passed",
            "assessor",
            "assessed_at",
            "remediation_summary",
        ])

        for control_id, evidence in sorted(package.evidence_by_control.items()):
            # Build a lookup from finding_id to result(s)
            results_by_finding: dict[str, list[dict[str, Any]]] = {}
            for r in evidence.results:
                results_by_finding.setdefault(r["finding_id"], []).append(r)

            for finding in evidence.findings:
                fid = finding["id"]
                related_results = results_by_finding.get(fid, [])

                if related_results:
                    for result in related_results:
                        writer.writerow([
                            evidence.framework,
                            control_id,
                            fid,
                            finding.get("title", ""),
                            finding.get("observation_type", ""),
                            finding.get("resource_id", ""),
                            finding.get("resource_type", ""),
                            finding.get("resource_name", ""),
                            finding.get("account_id", ""),
                            finding.get("region", ""),
                            finding.get("source", ""),
                            finding.get("source_type", ""),
                            finding.get("provider", ""),
                            finding.get("severity", ""),
                            finding.get("confidence", ""),
                            finding.get("observed_at", ""),
                            finding.get("ingested_at", ""),
                            result.get("status", ""),
                            result.get("assertion_name", ""),
                            result.get("assertion_passed", ""),
                            result.get("assessor", ""),
                            result.get("assessed_at", ""),
                            result.get("remediation_summary", ""),
                        ])
                else:
                    # Finding without a result in this period
                    writer.writerow([
                        evidence.framework,
                        control_id,
                        fid,
                        finding.get("title", ""),
                        finding.get("observation_type", ""),
                        finding.get("resource_id", ""),
                        finding.get("resource_type", ""),
                        finding.get("resource_name", ""),
                        finding.get("account_id", ""),
                        finding.get("region", ""),
                        finding.get("source", ""),
                        finding.get("source_type", ""),
                        finding.get("provider", ""),
                        finding.get("severity", ""),
                        finding.get("confidence", ""),
                        finding.get("observed_at", ""),
                        finding.get("ingested_at", ""),
                        "",  # no assessment status
                        "",
                        "",
                        "",
                        "",
                        "",
                    ])

        return output.getvalue()
