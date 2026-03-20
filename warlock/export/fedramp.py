"""FedRAMP package generation: SSP template, CRM, CIS, and ConMon plan.

Produces structured dicts suitable for JSON serialisation or further
rendering into FedRAMP Appendix documents.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from warlock.db.models import (
    ControlInheritance,
    ControlMapping,
    ControlResult,
    SystemProfile,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FRAMEWORKS_DIR = Path(__file__).resolve().parent.parent / "frameworks"


def _load_framework_yaml(framework_id: str) -> dict[str, Any]:
    """Load a framework YAML from the frameworks directory."""
    path = _FRAMEWORKS_DIR / f"{framework_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"Framework YAML not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _iter_controls(config: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Yield (family_id, control_id, control_dict) from framework YAML."""
    results: list[tuple[str, str, dict[str, Any]]] = []
    for family_id, family in config.get("control_families", {}).items():
        for control_id, control in family.get("controls", {}).items():
            results.append((family_id, control_id, control))
    return results


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Status aggregation
# ---------------------------------------------------------------------------

_STATUS_PRIORITY = {
    "non_compliant": 0,
    "partial": 1,
    "not_assessed": 2,
    "compliant": 3,
    "not_applicable": 4,
}


def _aggregate_status(statuses: list[str]) -> str:
    """Pick the worst-case status from a list."""
    if not statuses:
        return "not_assessed"
    return min(statuses, key=lambda s: _STATUS_PRIORITY.get(s, 2))


def _impl_label(status: str) -> str:
    return {
        "compliant": "Implemented",
        "partial": "Partially Implemented",
        "non_compliant": "Planned",
        "not_assessed": "Not Assessed",
        "not_applicable": "Not Applicable",
    }.get(status, "Not Assessed")


# ---------------------------------------------------------------------------
# FedRAMPPackageGenerator
# ---------------------------------------------------------------------------


class FedRAMPPackageGenerator:
    """Generates FedRAMP package artefacts from Warlock pipeline data."""

    # ------------------------------------------------------------------
    # SSP Template
    # ------------------------------------------------------------------

    def generate_ssp_template(
        self,
        session: Session,
        system_profile_id: str,
    ) -> dict[str, Any]:
        """Return a structured dict with FedRAMP SSP sections.

        Populated from SystemProfile metadata and ControlResult data.
        """
        profile = (
            session.query(SystemProfile)
            .filter(SystemProfile.id == system_profile_id)
            .first()
        )
        if profile is None:
            raise ValueError(f"SystemProfile {system_profile_id} not found")

        # Gather latest control results for fedramp
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == "fedramp",
                ControlResult.system_profile_id == system_profile_id,
            )
            .all()
        )

        # Build per-control status map
        ctrl_statuses: dict[str, list[str]] = {}
        ctrl_details: dict[str, list[str]] = {}
        for cr in results:
            ctrl_statuses.setdefault(cr.control_id, []).append(cr.status)
            desc = cr.ai_assessment or cr.remediation_summary or ""
            if desc:
                ctrl_details.setdefault(cr.control_id, []).append(desc)

        # Load FedRAMP YAML for control catalogue
        fedramp_config = _load_framework_yaml("fedramp")
        control_entries = []
        for family_id, control_id, control in _iter_controls(fedramp_config):
            statuses = ctrl_statuses.get(control_id, [])
            agg = _aggregate_status(statuses)
            control_entries.append({
                "control_id": control_id,
                "family": family_id,
                "title": control.get("title", ""),
                "description": control.get("description", ""),
                "implementation_status": _impl_label(agg),
                "implementation_details": ctrl_details.get(control_id, []),
            })

        # Counts
        total = len(control_entries)
        implemented = sum(1 for c in control_entries if c["implementation_status"] == "Implemented")

        return {
            "document_type": "FedRAMP SSP",
            "generated_at": _now_iso(),
            "system_description": {
                "system_name": profile.name,
                "system_acronym": profile.acronym or "",
                "description": profile.description or "",
                "deployment_model": profile.deployment_model or "cloud",
                "service_model": profile.service_model or "SaaS",
                "authorization_status": profile.authorization_status,
                "authorization_date": (
                    profile.authorization_date.isoformat()
                    if profile.authorization_date
                    else None
                ),
            },
            "security_objectives": {
                "confidentiality": profile.confidentiality_impact or "moderate",
                "integrity": profile.integrity_impact or "moderate",
                "availability": profile.availability_impact or "moderate",
                "overall_impact": profile.overall_impact or "moderate",
            },
            "system_environment": {
                "cloud_accounts": profile.cloud_accounts or [],
                "network_boundaries": profile.network_boundaries or [],
                "connector_scope": profile.connector_scope or [],
            },
            "system_interconnections": profile.interconnections or [],
            "responsible_parties": {
                "system_owner": profile.system_owner,
                "system_owner_email": profile.system_owner_email,
                "isso": profile.isso,
                "isso_email": profile.isso_email,
                "issm": profile.issm,
                "issm_email": profile.issm_email,
                "authorizing_official": profile.authorizing_official,
                "ao_email": profile.ao_email,
            },
            "control_summary": {
                "total_controls": total,
                "implemented": implemented,
                "not_implemented": total - implemented,
            },
            "controls": control_entries,
        }

    # ------------------------------------------------------------------
    # Customer Responsibility Matrix (CRM)
    # ------------------------------------------------------------------

    def generate_crm(
        self,
        session: Session,
        system_profile_id: str,
    ) -> dict[str, Any]:
        """Customer Responsibility Matrix from ControlInheritance data."""
        rows = (
            session.query(ControlInheritance)
            .filter(ControlInheritance.system_profile_id == system_profile_id)
            .all()
        )

        entries: list[dict[str, Any]] = []
        for ci in rows:
            entries.append({
                "framework": ci.framework,
                "control_id": ci.control_id,
                "inheritance_type": ci.inheritance_type,
                "provider_description": ci.provider_description or "",
                "responsibility_description": ci.responsibility_description or "",
                "evidence_requirement": ci.evidence_requirement or "both",
                "status": ci.status,
            })

        # Summarise by type
        type_counts: dict[str, int] = {}
        for e in entries:
            t = e["inheritance_type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "document_type": "FedRAMP CRM",
            "generated_at": _now_iso(),
            "system_profile_id": system_profile_id,
            "summary": type_counts,
            "total_controls": len(entries),
            "entries": entries,
        }

    # ------------------------------------------------------------------
    # Control Implementation Summary (CIS)
    # ------------------------------------------------------------------

    def generate_cis(
        self,
        session: Session,
        framework: str,
        system_profile_id: str,
    ) -> dict[str, Any]:
        """Control Implementation Summary: one entry per control.

        Includes status, implementation description from assertion results,
        and responsible role.
        """
        config = _load_framework_yaml(framework)
        all_controls = _iter_controls(config)

        # Latest results per control
        results = (
            session.query(ControlResult)
            .filter(
                ControlResult.framework == framework,
                ControlResult.system_profile_id == system_profile_id,
            )
            .all()
        )

        ctrl_map: dict[str, list[ControlResult]] = {}
        for cr in results:
            ctrl_map.setdefault(cr.control_id, []).append(cr)

        # Inheritance info
        inheritances = (
            session.query(ControlInheritance)
            .filter(
                ControlInheritance.system_profile_id == system_profile_id,
                ControlInheritance.framework == framework,
            )
            .all()
        )
        inh_map: dict[str, ControlInheritance] = {ci.control_id: ci for ci in inheritances}

        entries: list[dict[str, Any]] = []
        for family_id, control_id, control in all_controls:
            crs = ctrl_map.get(control_id, [])
            statuses = [cr.status for cr in crs]
            agg = _aggregate_status(statuses)

            # Build description from assertion findings
            descriptions: list[str] = []
            for cr in crs:
                if cr.ai_assessment:
                    descriptions.append(cr.ai_assessment)
                elif cr.assertion_findings:
                    if isinstance(cr.assertion_findings, list):
                        descriptions.extend(str(f) for f in cr.assertion_findings)
                    else:
                        descriptions.append(str(cr.assertion_findings))

            ci = inh_map.get(control_id)
            responsible_role = "Customer"
            if ci:
                if ci.inheritance_type == "inherited":
                    responsible_role = "Provider"
                elif ci.inheritance_type == "shared":
                    responsible_role = "Shared"
                elif ci.inheritance_type == "common":
                    responsible_role = "Common"

            entries.append({
                "control_id": control_id,
                "family": family_id,
                "title": control.get("title", ""),
                "implementation_status": _impl_label(agg),
                "implementation_description": " | ".join(descriptions[:5]) if descriptions else "",
                "responsible_role": responsible_role,
                "inheritance_type": ci.inheritance_type if ci else "system_specific",
            })

        return {
            "document_type": "FedRAMP CIS",
            "generated_at": _now_iso(),
            "framework": framework,
            "system_profile_id": system_profile_id,
            "total_controls": len(entries),
            "entries": entries,
        }

    # ------------------------------------------------------------------
    # Continuous Monitoring (ConMon) Plan
    # ------------------------------------------------------------------

    def generate_conmon_plan(
        self,
        session: Session,
    ) -> dict[str, Any]:
        """ConMon plan template with scan schedules and assessment frequencies.

        Derives frequencies from the monitoring_frequency fields in all
        loaded framework YAMLs.
        """
        frequency_map: dict[str, list[dict[str, str]]] = {}

        # Scan all framework YAMLs for monitoring_frequency
        for yaml_path in sorted(_FRAMEWORKS_DIR.glob("*.yaml")):
            if yaml_path.name.startswith("crosswalk"):
                continue
            try:
                config = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            except Exception:
                log.debug("Skipping %s", yaml_path.name, exc_info=True)
                continue

            fw_id = config.get("framework_id", yaml_path.stem)
            for _family_id, control_id, control in _iter_controls(config):
                freq = control.get("monitoring_frequency")
                if not freq:
                    # Check if any check has a monitoring_frequency
                    for check in control.get("checks", []):
                        freq = check.get("monitoring_frequency")
                        if freq:
                            break
                if freq:
                    frequency_map.setdefault(freq, []).append({
                        "framework": fw_id,
                        "control_id": control_id,
                    })

        # Distinct active frameworks from ControlMapping
        active_frameworks = [
            row[0]
            for row in session.query(ControlMapping.framework).distinct().all()
        ]

        return {
            "document_type": "FedRAMP ConMon Plan",
            "generated_at": _now_iso(),
            "active_frameworks": sorted(active_frameworks),
            "scan_schedules": {
                "vulnerability_scanning": {
                    "frequency": "monthly",
                    "description": "OS, infrastructure, and web application vulnerability scans",
                },
                "configuration_scanning": {
                    "frequency": "monthly",
                    "description": "CIS benchmark and STIG compliance scans",
                },
                "penetration_testing": {
                    "frequency": "annual",
                    "description": "Third-party penetration test (3PAO)",
                },
            },
            "assessment_frequencies": {
                freq: {
                    "control_count": len(controls),
                    "controls": controls,
                }
                for freq, controls in sorted(frequency_map.items())
            },
            "reporting_cadence": {
                "monthly": "ConMon deliverables: scan results, POA&M updates, significant change reports",
                "quarterly": "Quarterly posture review with AO",
                "annual": "Full 3PAO assessment, ATO renewal",
            },
        }
