"""SOC 2 Type II historical evidence retention and continuous coverage verification.

Provides evidence snapshot creation, period verification, and gap detection
using existing ControlResult.assessed_at timestamps.

Phase 2 additions:
- ``evaluate_evidence_quality()`` — AI-enhanced evidence sufficiency scoring.
  Returns relevance, completeness, timeliness, and authenticity scores per
  artifact.  Falls back to a presence/absence heuristic when AI is off.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from dateutil.relativedelta import relativedelta
from sqlalchemy.orm import Session

from warlock.db.models import ControlResult, Finding, RawEvent
from warlock.utils import ensure_aware

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _month_ranges(
    period_start: datetime,
    period_end: datetime,
) -> list[tuple[datetime, datetime]]:
    """Break a date range into per-month intervals.

    Returns a list of (month_start, month_end) tuples.
    """
    ranges: list[tuple[datetime, datetime]] = []
    current = ensure_aware(period_start).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = ensure_aware(period_end)
    while current < end:
        next_month = current + relativedelta(months=1)
        month_end = min(next_month, end)
        ranges.append((current, month_end))
        current = next_month
    return ranges


def _controls_for_framework(
    session: Session,
    framework: str,
) -> list[str]:
    """Return all distinct control IDs that have ever been assessed for a framework."""
    rows = (
        session.query(ControlResult.control_id)
        .filter(ControlResult.framework == framework)
        .distinct()
        .all()
    )
    return sorted(row[0] for row in rows)


# ---------------------------------------------------------------------------
# EvidenceRetentionManager
# ---------------------------------------------------------------------------


class EvidenceRetentionManager:
    """Manages SOC 2 Type II historical evidence retention and verification."""

    def create_evidence_snapshot(
        self,
        session: Session,
        framework: str,
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Any]:
        """Capture all control results, findings, and raw events for a framework
        within a date range and create a signed evidence package.

        The "signature" is a SHA-256 hash of the serialised evidence content,
        providing tamper-evidence (not cryptographic non-repudiation).
        """
        start = ensure_aware(period_start)
        end = ensure_aware(period_end)

        # Control results in period
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.assessed_at >= start,
                ControlResult.assessed_at <= end,
            )
            .order_by(ControlResult.assessed_at)
            .all()
        )

        result_dicts = [
            {
                "id": cr.id,
                "control_id": cr.control_id,
                "status": cr.status,
                "severity": cr.severity,
                "assessor": cr.assessor,
                "assessed_at": cr.assessed_at.isoformat() if cr.assessed_at else None,
                "assertion_name": cr.assertion_name,
                "assertion_passed": cr.assertion_passed,
            }
            for cr in results
        ]

        # Related findings
        finding_ids = {cr.finding_id for cr in results if cr.finding_id}
        findings: list[dict[str, Any]] = []
        if finding_ids:
            finding_rows = session.query(Finding).filter(Finding.id.in_(finding_ids)).all()
            findings = [
                {
                    "id": f.id,
                    "title": f.title,
                    "observation_type": f.observation_type,
                    "severity": f.severity,
                    "resource_id": f.resource_id,
                    "observed_at": f.observed_at.isoformat() if f.observed_at else None,
                }
                for f in finding_rows
            ]

        # Raw events in period, filtered by framework
        # Derive event sources that belong to this framework from the
        # control results already queried above.
        framework_sources = {cr.source for cr in results if getattr(cr, "source", None)}
        raw_event_query = session.query(RawEvent).filter(
            RawEvent.ingested_at >= start,
            RawEvent.ingested_at <= end,
        )
        if framework_sources:
            raw_event_query = raw_event_query.filter(RawEvent.source.in_(framework_sources))
        raw_events = raw_event_query.all()
        raw_event_dicts = [
            {
                "id": re.id,
                "source": re.source,
                "event_type": re.event_type,
                "sha256": re.sha256,
                "ingested_at": re.ingested_at.isoformat() if re.ingested_at else None,
            }
            for re in raw_events
        ]

        # Build snapshot
        snapshot_content = {
            "control_results": result_dicts,
            "findings": findings,
            "raw_events": raw_event_dicts,
        }

        # Compute content hash for tamper evidence
        canonical = json.dumps(snapshot_content, sort_keys=True, default=str)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        # Distinct controls covered
        controls_covered = sorted({cr.control_id for cr in results})

        return {
            "document_type": "Evidence Snapshot",
            "framework": framework,
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "content_hash": content_hash,
            "summary": {
                "control_results": len(result_dicts),
                "findings": len(findings),
                "raw_events": len(raw_event_dicts),
                "controls_covered": len(controls_covered),
            },
            "controls_covered": controls_covered,
            "content": snapshot_content,
        }

    def verify_evidence_period(
        self,
        session: Session,
        framework: str,
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Any]:
        """Check that evidence exists for every control for every month in the period.

        This proves continuous operation for SOC 2 Type II audits.
        """
        start = ensure_aware(period_start)
        end = ensure_aware(period_end)
        months = _month_ranges(start, end)
        all_controls = _controls_for_framework(session, framework)

        if not all_controls:
            return {
                "verified": False,
                "framework": framework,
                "period_start": start.isoformat(),
                "period_end": end.isoformat(),
                "reason": "No controls found for framework",
                "total_controls": 0,
                "months_checked": len(months),
                "coverage": {},
            }

        coverage: dict[str, dict[str, bool]] = {}
        all_covered = True

        for month_start, month_end in months:
            month_key = month_start.strftime("%Y-%m")
            # Get controls that have at least one result in this month
            covered_controls = {
                row[0]
                for row in (
                    session.query(ControlResult.control_id)
                    .filter(
                        ControlResult.framework == framework,
                        ControlResult.assessed_at >= month_start,
                        ControlResult.assessed_at < month_end,
                    )
                    .distinct()
                    .all()
                )
            }

            month_coverage: dict[str, bool] = {}
            for ctrl in all_controls:
                has_evidence = ctrl in covered_controls
                month_coverage[ctrl] = has_evidence
                if not has_evidence:
                    all_covered = False

            coverage[month_key] = month_coverage

        return {
            "verified": all_covered,
            "framework": framework,
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "total_controls": len(all_controls),
            "months_checked": len(months),
            "coverage": coverage,
        }

    def get_evidence_gaps(
        self,
        session: Session,
        framework: str,
        period_start: datetime,
        period_end: datetime,
    ) -> list[dict[str, Any]]:
        """Return controls that have no evidence for any month in the period.

        Each gap entry includes the control_id and the months lacking evidence.
        """
        verification = self.verify_evidence_period(
            session,
            framework,
            period_start,
            period_end,
        )

        if not verification["coverage"]:
            return []

        # Invert: for each control, find months with no evidence
        all_controls: set[str] = set()
        for month_data in verification["coverage"].values():
            all_controls.update(month_data.keys())

        gaps: list[dict[str, Any]] = []
        for ctrl in sorted(all_controls):
            missing_months: list[str] = []
            for month_key, month_data in sorted(verification["coverage"].items()):
                if not month_data.get(ctrl, False):
                    missing_months.append(month_key)

            if missing_months:
                gaps.append(
                    {
                        "control_id": ctrl,
                        "missing_months": missing_months,
                        "gap_count": len(missing_months),
                        "total_months": verification["months_checked"],
                    }
                )

        return gaps


# ---------------------------------------------------------------------------
# AI-enhanced evidence quality evaluation
# ---------------------------------------------------------------------------


def _fallback_evidence_quality(
    control_id: str,
    evidence_artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Deterministic presence/absence evidence quality check.

    Used as the fallback when AI is off.  Scores are binary:
    1.0 if the artifact exists and has content, 0.0 otherwise.

    Args:
        control_id: The control being evaluated.
        evidence_artifacts: List of artifact dicts, each expected to
            have at least ``type`` and optionally ``content``,
            ``collected_at``, ``hash``.

    Returns:
        Dict with per-artifact scores and an overall summary.
    """
    artifact_scores: list[dict[str, Any]] = []

    for artifact in evidence_artifacts:
        has_content = bool(artifact.get("content") or artifact.get("data"))
        has_timestamp = bool(artifact.get("collected_at") or artifact.get("timestamp"))
        has_hash = bool(artifact.get("hash") or artifact.get("sha256"))

        score = {
            "artifact_type": artifact.get("type", "unknown"),
            "relevance": 1.0 if has_content else 0.0,
            "completeness": 1.0 if has_content else 0.0,
            "timeliness": 1.0 if has_timestamp else 0.0,
            "authenticity": 1.0 if has_hash else 0.0,
        }
        artifact_scores.append(score)

    # Overall scores: average across artifacts
    n = len(artifact_scores)
    if n == 0:
        return {
            "control_id": control_id,
            "artifacts": [],
            "overall": {
                "relevance": 0.0,
                "completeness": 0.0,
                "timeliness": 0.0,
                "authenticity": 0.0,
            },
            "ai_used": False,
        }

    return {
        "control_id": control_id,
        "artifacts": artifact_scores,
        "overall": {
            "relevance": round(sum(a["relevance"] for a in artifact_scores) / n, 4),
            "completeness": round(sum(a["completeness"] for a in artifact_scores) / n, 4),
            "timeliness": round(sum(a["timeliness"] for a in artifact_scores) / n, 4),
            "authenticity": round(sum(a["authenticity"] for a in artifact_scores) / n, 4),
        },
        "ai_used": False,
    }


def evaluate_evidence_quality(
    session: Session,
    control_id: str,
    evidence_artifacts: list[dict[str, Any]],
    control_description: str = "",
) -> dict[str, Any]:
    """Evaluate the quality and sufficiency of evidence artifacts for a control.

    When AI is enabled, calls ``AIService.reason(AITask.EVIDENCE_EVALUATION,
    ...)`` with the artifact metadata and control description.  The model
    assesses each artifact on four dimensions:

    - **relevance** -- does the evidence address the control requirement?
    - **completeness** -- does it cover the full scope of the control?
    - **timeliness** -- is the evidence current enough for audit purposes?
    - **authenticity** -- can the evidence be verified (hashes, signatures)?

    When AI is off, falls back to a deterministic presence/absence check
    that scores each dimension as 1.0 or 0.0 based on whether the artifact
    dict contains the expected fields.

    Args:
        session: SQLAlchemy database session (available for future
            enrichment queries).
        control_id: The control identifier being evaluated.
        evidence_artifacts: List of artifact dicts.  Each should contain
            at minimum ``type`` and ideally ``content``, ``collected_at``,
            and ``hash`` or ``sha256``.
        control_description: Optional human-readable description of the
            control requirement for AI context.

    Returns:
        A dict with per-artifact scores, overall aggregated scores, and
        an ``ai_used`` boolean indicating provenance.
    """
    from warlock.ai import AITask, get_ai_service

    ai = get_ai_service()

    # Sanitize artifacts for the prompt: strip large content payloads
    artifact_summaries = []
    for artifact in evidence_artifacts:
        summary = {
            "type": artifact.get("type", "unknown"),
            "collected_at": artifact.get("collected_at") or artifact.get("timestamp"),
            "has_content": bool(artifact.get("content") or artifact.get("data")),
            "has_hash": bool(artifact.get("hash") or artifact.get("sha256")),
            "metadata": {
                k: v for k, v in artifact.items() if k not in ("content", "data", "body", "raw")
            },
        }
        artifact_summaries.append(summary)

    context = {
        "control_id": control_id,
        "control_description": control_description,
        "artifacts": artifact_summaries,
        "artifact_count": len(evidence_artifacts),
    }

    result = ai.reason(
        task=AITask.EVIDENCE_EVALUATION,
        context=context,
        fallback=lambda: _fallback_evidence_quality(control_id, evidence_artifacts),
    )

    if result.ai_used and isinstance(result.value, dict):
        # Normalize AI response into our expected schema
        ai_value = result.value
        return {
            "control_id": control_id,
            "evaluation": ai_value.get("evaluation", ""),
            "sufficient": ai_value.get("sufficient", False),
            "overall": {
                "relevance": ai_value.get("relevance", 0.0),
                "completeness": ai_value.get("completeness", 0.0),
                "timeliness": ai_value.get("timeliness", 0.0),
                "authenticity": ai_value.get("authenticity", 0.0),
            },
            "ai_used": True,
            "ai_model": result.model,
            "ai_confidence": result.confidence,
        }

    # Fallback response
    value = result.value
    if isinstance(value, dict):
        return value

    return _fallback_evidence_quality(control_id, evidence_artifacts)
