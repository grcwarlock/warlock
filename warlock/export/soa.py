"""ISO 27001 Statement of Applicability (SoA) export.

Produces a complete SoA covering every Annex A control from the
iso_27001.yaml framework definition, with implementation status
derived from ControlResult data and applicability from SystemProfile.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from warlock.db.models import ControlResult, SystemProfile

log = logging.getLogger(__name__)

_FRAMEWORKS_DIR = Path(__file__).resolve().parent.parent / "frameworks"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_iso27001_controls() -> list[dict[str, Any]]:
    """Parse iso_27001.yaml and return a flat list of control dicts.

    Each entry: {control_id, family, title, checks, monitoring_frequency}.
    """
    path = _FRAMEWORKS_DIR / "iso_27001.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"ISO 27001 YAML not found: {path}")

    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    controls: list[dict[str, Any]] = []
    for family_id, family in config.get("control_families", {}).items():
        family_name = family.get("name", family_id)
        for control_id, control in family.get("controls", {}).items():
            controls.append(
                {
                    "control_id": control_id,
                    "family": family_id,
                    "family_name": family_name,
                    "title": control.get("title", ""),
                    "monitoring_frequency": control.get("monitoring_frequency", ""),
                    "checks": control.get("checks", []),
                }
            )
    return controls


def _impl_status_label(status: str) -> str:
    return {
        "compliant": "Implemented",
        "partial": "Partially Implemented",
        "non_compliant": "Not Implemented",
        "not_assessed": "Not Assessed",
        "not_applicable": "Not Applicable",
    }.get(status, "Not Assessed")


_STATUS_PRIORITY = {
    "non_compliant": 0,
    "partial": 1,
    "not_assessed": 2,
    "compliant": 3,
    "not_applicable": 4,
}


def _aggregate_status(statuses: list[str]) -> str:
    if not statuses:
        return "not_assessed"
    return min(statuses, key=lambda s: _STATUS_PRIORITY.get(s, 2))


# ---------------------------------------------------------------------------
# StatementOfApplicability
# ---------------------------------------------------------------------------


class StatementOfApplicability:
    """Generates ISO 27001:2022 Statement of Applicability."""

    def generate(
        self,
        session: Session,
        system_profile_id: str,
    ) -> dict[str, Any]:
        """Produce an SoA dict covering every ISO 27001 Annex A control.

        For each control:
        - Whether it is applicable (based on SystemProfile.frameworks)
        - Implementation status from the latest ControlResult
        - Justification (if applicable or excluded)
        - Control objective reference
        - Implementation evidence summary
        """
        profile = session.query(SystemProfile).filter(SystemProfile.id == system_profile_id).first()
        if profile is None:
            raise ValueError(f"SystemProfile {system_profile_id} not found")

        applicable = "iso_27001" in (profile.frameworks or [])

        # Fetch all ISO 27001 control results for this system
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == "iso_27001",
                ControlResult.system_profile_id == system_profile_id,
            )
            .all()
        )

        # Group results by control_id
        ctrl_results: dict[str, list[ControlResult]] = {}
        for cr in results:
            ctrl_results.setdefault(cr.control_id, []).append(cr)

        # Load the full Annex A catalogue
        annex_a = _load_iso27001_controls()

        soa_entries: list[dict[str, Any]] = []
        for ctrl in annex_a:
            cid = ctrl["control_id"]
            crs = ctrl_results.get(cid, [])

            if applicable and crs:
                statuses = [cr.status for cr in crs]
                agg = _aggregate_status(statuses)

                # Build justification from assessment data
                justifications: list[str] = []
                evidence_refs: list[str] = []
                for cr in crs:
                    if cr.ai_assessment:
                        justifications.append(cr.ai_assessment)
                    elif cr.assertion_findings and isinstance(cr.assertion_findings, list):
                        justifications.extend(str(f) for f in cr.assertion_findings)
                    if cr.assertion_name:
                        evidence_refs.append(cr.assertion_name)

                soa_entries.append(
                    {
                        "control_id": cid,
                        "family": ctrl["family"],
                        "family_name": ctrl["family_name"],
                        "title": ctrl["title"],
                        "applicable": True,
                        "implementation_status": _impl_status_label(agg),
                        "justification": " | ".join(justifications[:3])
                        if justifications
                        else "Control assessed via automated pipeline",
                        "exclusion_justification": None,
                        "control_objective": ctrl["title"],
                        "evidence_summary": ", ".join(sorted(set(evidence_refs)))
                        if evidence_refs
                        else "Pipeline assessment data",
                    }
                )
            elif applicable:
                # Framework is in scope but no results yet
                soa_entries.append(
                    {
                        "control_id": cid,
                        "family": ctrl["family"],
                        "family_name": ctrl["family_name"],
                        "title": ctrl["title"],
                        "applicable": True,
                        "implementation_status": "Not Assessed",
                        "justification": "No assessment data collected yet",
                        "exclusion_justification": None,
                        "control_objective": ctrl["title"],
                        "evidence_summary": "",
                    }
                )
            else:
                # ISO 27001 not in scope for this system
                soa_entries.append(
                    {
                        "control_id": cid,
                        "family": ctrl["family"],
                        "family_name": ctrl["family_name"],
                        "title": ctrl["title"],
                        "applicable": False,
                        "implementation_status": "Not Applicable",
                        "justification": None,
                        "exclusion_justification": "ISO 27001 is not within the scope of this system profile",
                        "control_objective": ctrl["title"],
                        "evidence_summary": "",
                    }
                )

        total = len(soa_entries)
        applicable_count = sum(1 for e in soa_entries if e["applicable"])
        implemented = sum(1 for e in soa_entries if e["implementation_status"] == "Implemented")

        return {
            "document_type": "ISO 27001:2022 Statement of Applicability",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "system_profile": {
                "id": profile.id,
                "name": profile.name,
                "acronym": profile.acronym or "",
            },
            "summary": {
                "total_controls": total,
                "applicable": applicable_count,
                "not_applicable": total - applicable_count,
                "implemented": implemented,
                "not_implemented": applicable_count - implemented,
            },
            "entries": soa_entries,
        }

    def export_json(
        self,
        session: Session,
        system_profile_id: str,
    ) -> str:
        """JSON string export of the SoA."""
        data = self.generate(session, system_profile_id)
        return json.dumps(data, indent=2, default=str)

    def export_csv(
        self,
        session: Session,
        system_profile_id: str,
    ) -> str:
        """CSV export for auditors who prefer spreadsheets."""
        data = self.generate(session, system_profile_id)
        # SEC-C11: neutralize spreadsheet formula prefixes via a writer adapter.
        from warlock.utils.csv_safety import neutralize_list

        output = io.StringIO()
        _raw_writer = csv.writer(output)

        def _safe_writerow(row):
            _raw_writer.writerow(neutralize_list(list(row)))

        _safe_writerow(
            [
                "Control ID",
                "Family",
                "Title",
                "Applicable",
                "Implementation Status",
                "Justification",
                "Exclusion Justification",
                "Control Objective",
                "Evidence Summary",
            ]
        )
        for entry in data["entries"]:
            _safe_writerow(
                [
                    entry["control_id"],
                    entry["family"],
                    entry["title"],
                    "Yes" if entry["applicable"] else "No",
                    entry["implementation_status"],
                    entry.get("justification") or "",
                    entry.get("exclusion_justification") or "",
                    entry["control_objective"],
                    entry.get("evidence_summary") or "",
                ]
            )
        return output.getvalue()
