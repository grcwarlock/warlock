"""SOC 2 Type II historical evidence retention and continuous coverage verification.

Provides evidence snapshot creation, period verification, and gap detection
using existing ControlResult.assessed_at timestamps.
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
            finding_rows = (
                session.query(Finding)
                .filter(Finding.id.in_(finding_ids))
                .all()
            )
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

        # Raw events in period
        raw_events = (
            session.query(RawEvent)
            .filter(
                RawEvent.ingested_at >= start,
                RawEvent.ingested_at <= end,
            )
            .all()
        )
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
            session, framework, period_start, period_end,
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
                gaps.append({
                    "control_id": ctrl,
                    "missing_months": missing_months,
                    "gap_count": len(missing_months),
                    "total_months": verification["months_checked"],
                })

        return gaps
