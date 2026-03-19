"""Audit binder generation.

Creates a structured ZIP file organized by control family with
evidence, POA&Ms, compensating controls, and risk acceptances
per control. Designed for auditor consumption.
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from warlock.db.models import (
    AuditEngagement,
    CompensatingControl,
    ControlResult,
    Finding,
    POAM,
    RiskAcceptance,
)

log = logging.getLogger(__name__)


def _json_serial(obj):
    """JSON serializer for datetime and other non-serializable types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


class AuditBinderGenerator:
    """Generates a structured ZIP binder for an audit engagement."""

    def generate(
        self,
        session: Session,
        engagement_id: str,
        output_path: str,
    ) -> str:
        """Create a ZIP file organized by control_family/control_id.

        Structure:
            binder/
              summary.json          — engagement metadata + coverage stats
              {control_family}/
                {control_id}/
                  evidence.json     — raw findings and control results
                  poams.json        — related POA&Ms
                  compensating.json — related compensating controls
                  acceptances.json  — related risk acceptances

        Args:
            session: SQLAlchemy session.
            engagement_id: ID of the AuditEngagement.
            output_path: Filesystem path for the output ZIP.

        Returns:
            The output path.

        Raises:
            ValueError: If engagement not found.
        """
        engagement = session.get(AuditEngagement,engagement_id)
        if not engagement:
            raise ValueError(f"Engagement not found: {engagement_id}")

        # Query all control results within the engagement period
        query = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == engagement.framework,
                ControlResult.assessed_at >= engagement.period_start,
                ControlResult.assessed_at <= engagement.period_end,
            )
        )

        in_scope = engagement.in_scope_controls or []
        excluded = engagement.excluded_controls or []
        if in_scope:
            query = query.filter(ControlResult.control_id.in_(in_scope))
        if excluded:
            query = query.filter(~ControlResult.control_id.in_(excluded))

        results = query.all()

        # Group by control family / control_id
        controls: dict[str, dict[str, list[ControlResult]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for r in results:
            family = self._extract_family(r.control_id)
            controls[family][r.control_id].append(r)

        # Build summary
        total_controls = sum(
            len(cids) for cids in controls.values()
        )
        compliant_count = sum(
            1
            for family_map in controls.values()
            for cid, crs in family_map.items()
            if any(cr.status == "compliant" for cr in crs)
        )

        summary = {
            "engagement_id": engagement.id,
            "engagement_name": engagement.name,
            "framework": engagement.framework,
            "period_start": engagement.period_start,
            "period_end": engagement.period_end,
            "generated_at": datetime.now(timezone.utc),
            "total_controls": total_controls,
            "compliant_controls": compliant_count,
            "coverage_pct": round(
                (compliant_count / total_controls * 100) if total_controls else 0, 2
            ),
            "control_families": sorted(controls.keys()),
        }

        # W-11: Validate output path is under an allowed directory
        import tempfile

        resolved = Path(output_path).resolve()
        allowed_prefixes = (
            Path("exports").resolve(),
            Path("/tmp").resolve(),
            Path(tempfile.gettempdir()).resolve(),
        )
        if not any(
            str(resolved).startswith(str(prefix))
            for prefix in allowed_prefixes
        ):
            raise ValueError(
                f"Output path {resolved} is not under an allowed directory "
                f"(exports/ or /tmp/)"
            )

        # Write ZIP
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
            # Summary
            zf.writestr(
                "binder/summary.json",
                json.dumps(summary, indent=2, default=_json_serial),
            )

            for family, cid_map in sorted(controls.items()):
                for cid, crs in sorted(cid_map.items()):
                    # W-1: Sanitize to prevent ZIP path traversal
                    family = re.sub(r'[^a-zA-Z0-9._()-]', '_', family)
                    cid = re.sub(r'[^a-zA-Z0-9._()-]', '_', cid)
                    prefix = f"binder/{family}/{cid}"

                    # Evidence: control results + linked findings
                    evidence = self._build_evidence(session, crs)
                    zf.writestr(
                        f"{prefix}/evidence.json",
                        json.dumps(evidence, indent=2, default=_json_serial),
                    )

                    # POA&Ms
                    poams = self._get_poams(
                        session, engagement.framework, cid
                    )
                    if poams:
                        zf.writestr(
                            f"{prefix}/poams.json",
                            json.dumps(poams, indent=2, default=_json_serial),
                        )

                    # Compensating controls
                    comps = self._get_compensating(
                        session, engagement.framework, cid
                    )
                    if comps:
                        zf.writestr(
                            f"{prefix}/compensating.json",
                            json.dumps(comps, indent=2, default=_json_serial),
                        )

                    # Risk acceptances
                    acceptances = self._get_acceptances(
                        session, engagement.framework, cid
                    )
                    if acceptances:
                        zf.writestr(
                            f"{prefix}/acceptances.json",
                            json.dumps(
                                acceptances, indent=2, default=_json_serial
                            ),
                        )

        log.info(
            "Generated audit binder at %s: %d families, %d controls",
            output_path,
            len(controls),
            total_controls,
        )
        return output_path

    @staticmethod
    def _extract_family(control_id: str) -> str:
        """Extract control family from control_id.

        Examples:
            AC-2 -> AC
            CC6.1 -> CC6
            A.5.15 -> A.5
        """
        # NIST-style: letters followed by dash
        if "-" in control_id:
            return control_id.split("-")[0]
        # SOC2-style: letters followed by digits and dot
        if "." in control_id:
            parts = control_id.split(".")
            return parts[0] if len(parts) <= 2 else f"{parts[0]}.{parts[1]}"
        return control_id

    @staticmethod
    def _build_evidence(
        session: Session,
        control_results: list[ControlResult],
    ) -> list[dict]:
        """Build evidence records from control results and their findings."""
        evidence: list[dict] = []
        for cr in control_results:
            entry: dict = {
                "control_result_id": cr.id,
                "status": cr.status,
                "severity": cr.severity,
                "assessed_at": cr.assessed_at,
                "assessor": cr.assessor,
                "assertion_name": cr.assertion_name,
                "assertion_passed": cr.assertion_passed,
            }

            # Attach finding detail
            if cr.finding_id:
                finding = session.get(Finding,cr.finding_id)
                if finding:
                    entry["finding"] = {
                        "id": finding.id,
                        "title": finding.title,
                        "observation_type": finding.observation_type,
                        "resource_id": finding.resource_id,
                        "resource_type": finding.resource_type,
                        "severity": finding.severity,
                        "source": finding.source,
                        "provider": finding.provider,
                        "observed_at": finding.observed_at,
                    }

            evidence.append(entry)
        return evidence

    @staticmethod
    def _get_poams(
        session: Session,
        framework: str,
        control_id: str,
    ) -> list[dict]:
        """Get POA&Ms for a control."""
        poams = (
            session.query(POAM)
            .filter(POAM.framework == framework, POAM.control_id == control_id)
            .all()
        )
        return [
            {
                "id": p.id,
                "status": p.status,
                "severity": p.severity,
                "weakness_description": p.weakness_description,
                "scheduled_completion": p.scheduled_completion,
                "actual_completion": p.actual_completion,
                "delay_count": p.delay_count,
                "milestones": p.milestones,
            }
            for p in poams
        ]

    @staticmethod
    def _get_compensating(
        session: Session,
        framework: str,
        control_id: str,
    ) -> list[dict]:
        """Get compensating controls for a control."""
        ccs = (
            session.query(CompensatingControl)
            .filter(
                CompensatingControl.original_framework == framework,
                CompensatingControl.original_control_id == control_id,
            )
            .all()
        )
        return [
            {
                "id": c.id,
                "title": c.title,
                "status": c.status,
                "description": c.description,
                "effectiveness_score": c.effectiveness_score,
                "approved_by": c.approved_by,
                "expiry_date": c.expiry_date,
            }
            for c in ccs
        ]

    @staticmethod
    def _get_acceptances(
        session: Session,
        framework: str,
        control_id: str,
    ) -> list[dict]:
        """Get risk acceptances for a control."""
        ras = (
            session.query(RiskAcceptance)
            .filter(
                RiskAcceptance.framework == framework,
                RiskAcceptance.control_id == control_id,
            )
            .all()
        )
        return [
            {
                "id": r.id,
                "status": r.status,
                "risk_level": r.risk_level,
                "risk_description": r.risk_description,
                "approved_by": r.approved_by,
                "expiry_date": r.expiry_date,
                "conditions": r.conditions,
            }
            for r in ras
        ]
