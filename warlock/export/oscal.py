"""OSCAL export engine for Warlock GRC pipeline.

Produces valid OSCAL JSON conforming to NIST SP 800-53 OSCAL 1.1.2 for three
model types: Assessment Results (AR), System Security Plan (SSP), and
Plan of Action & Milestones (POA&M).

When an AINarrator is provided, the SSP and POA&M exports are enriched with
AI-generated, framework-aware narratives — making them useful for any
framework (ISO 27001, SOC 2, ISO 27701, ISO 42001) not just NIST/FedRAMP.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4, uuid5

from sqlalchemy import func
from sqlalchemy.orm import Session

from warlock.db.models import ConnectorRun, ControlMapping, ControlResult, Finding

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSCAL_VERSION = "1.1.2"
WARLOCK_NS = UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")

_FRAMEWORK_PROFILE_URIS: dict[str, str] = {
    "nist_800_53": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
    "soc2": "#soc2-profile",
    "iso_27001": "#iso-27001-profile",
    "cis": "#cis-profile",
    "pci_dss": "#pci-dss-profile",
}

# Local OSCAL catalog paths (relative to project root).
# Maps framework_id → catalog JSON path within frameworks-oscal/.
_LOCAL_CATALOG_PATHS: dict[str, str] = {
    "nist_800_53": "frameworks-oscal/nist-800-53-oscal/catalog/catalog.json",
    "iso_27001": "frameworks-oscal/iso-27001-oscal/catalog/catalog.json",
    "soc2": "frameworks-oscal/soc2-oscal/catalog/catalog.json",
    "iso_42001": "frameworks-oscal/iso-42001-oscal/catalog/catalog.json",
    "iso_27701": "frameworks-oscal/iso-27701-oscal/catalog/catalog.json",
    "ucf": "frameworks-oscal/unified-controls-framework/catalog/ucf-catalog.json",
}


def _load_local_catalog(framework: str) -> str | None:
    """Load a local OSCAL catalog and return its UUID for use as a profile href.

    Walks up from this file to find the project root (where frameworks-oscal/ lives),
    then reads the catalog JSON and extracts the UUID.  Returns a ``#<uuid>`` href
    if successful, or ``None`` if no local catalog is available.
    """
    rel_path = _LOCAL_CATALOG_PATHS.get(framework)
    if not rel_path:
        return None

    # Resolve project root: this file is at warlock/export/oscal.py
    project_root = Path(__file__).resolve().parent.parent.parent
    catalog_path = project_root / rel_path
    if not catalog_path.is_file():
        log.debug("Local catalog not found for %s at %s", framework, catalog_path)
        return None

    try:
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
        # Handle both standard {"catalog": {...}} and non-standard root keys
        catalog_obj = data.get("catalog", data.get("ucf-catalog", data))
        uuid = catalog_obj.get("uuid")
        if uuid:
            log.debug("Using local catalog UUID %s for %s", uuid, framework)
            return f"#{uuid}"
        return None
    except Exception:
        log.debug("Failed to read local catalog for %s", framework, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _oscal_control_id(framework: str, control_id: str) -> str:
    """Convert a control ID to OSCAL format (lowercase, hyphens for dots/spaces/underscores).

    Examples:
        AC-2   -> ac-2
        CC6.1  -> cc6-1
        A.5.15 -> a-5-15
    """
    return control_id.lower().replace("_", "-").replace(" ", "-").replace(".", "-")


def _status_to_oscal(status: str) -> str:
    """Map Warlock assessment status to OSCAL finding target state."""
    mapping = {
        "compliant": "satisfied",
        "non_compliant": "not-satisfied",
        "partial": "other",
        "not_assessed": "other",
        "not_applicable": "not-applicable",
    }
    return mapping.get(status, "other")


def _impl_status(status: str) -> str:
    """Map Warlock status to OSCAL implementation-status vocabulary."""
    mapping = {
        "compliant": "implemented",
        "partial": "partial",
        "non_compliant": "planned",
        "not_assessed": "planned",
        "not_applicable": "not-applicable",
    }
    return mapping.get(status, "planned")


def _severity_to_oscal(severity: str) -> str:
    """Normalize severity to lowercase OSCAL-compatible token."""
    normalized = severity.strip().lower() if severity else "unknown"
    if normalized in ("critical", "high", "medium", "moderate", "low", "info", "none"):
        return normalized
    return "unknown"


def _build_metadata(title: str, version: str = "1.0.0") -> dict[str, Any]:
    """Build the standard OSCAL metadata block."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "title": title,
        "last-modified": now,
        "version": version,
        "oscal-version": OSCAL_VERSION,
        "roles": [
            {
                "id": "assessor",
                "title": "Automated Assessor",
            },
            {
                "id": "tool",
                "title": "Warlock GRC Pipeline",
            },
        ],
        "parties": [
            {
                "uuid": str(uuid5(WARLOCK_NS, "warlock-grc")),
                "type": "organization",
                "name": "Warlock GRC",
                "remarks": "Automated GRC assessment pipeline",
            }
        ],
    }


def _deterministic_uuid(*parts: str) -> str:
    """Generate a reproducible UUID5 from string parts."""
    return str(uuid5(WARLOCK_NS, "|".join(parts)))


def _iso(dt: datetime | None) -> str:
    """Datetime to ISO-8601 string, falling back to now."""
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _assessment_method(assessor: str | None) -> str:
    """Derive OSCAL assessment method from assessor string."""
    if not assessor:
        return "TEST"
    if assessor.startswith("ai:"):
        return "INTERVIEW"  # AI reasoning ~ interview analogy in OSCAL
    return "TEST"


# ---------------------------------------------------------------------------
# Core exporter
# ---------------------------------------------------------------------------


class OscalExporter:
    """Produces OSCAL-compliant JSON from the Warlock pipeline database."""

    # ------------------------------------------------------------------
    # Assessment Results
    # ------------------------------------------------------------------

    def export_assessment_results(
        self,
        session: Session,
        framework: str | None,
        system_name: str,
    ) -> dict[str, Any]:
        """Export OSCAL Assessment Results document.

        Args:
            session: SQLAlchemy session.
            framework: Limit to a single framework, or ``None`` for all.
            system_name: Human-readable system name for metadata.

        Returns:
            Complete OSCAL assessment-results dict ready for serialisation.
        """
        query = session.query(ControlResult)
        if framework:
            query = query.filter(ControlResult.framework == framework)

        results_rows: list[ControlResult] = query.all()
        if not results_rows:
            log.warning("No ControlResult rows found%s", f" for {framework}" if framework else "")

        # Group by framework
        by_framework: dict[str, list[ControlResult]] = {}
        for cr in results_rows:
            by_framework.setdefault(cr.framework, []).append(cr)

        # Pre-fetch related findings in bulk
        finding_ids = {cr.finding_id for cr in results_rows}
        findings_map: dict[str, Finding] = {}
        if finding_ids:
            for f in session.query(Finding).filter(Finding.id.in_(finding_ids)).all():
                findings_map[f.id] = f

        # Build per-framework result blocks
        oscal_results: list[dict[str, Any]] = []
        for fw, cr_list in sorted(by_framework.items()):
            oscal_results.append(
                self._build_result_block(fw, cr_list, findings_map, system_name)
            )

        doc_uuid = str(uuid4())
        return {
            "assessment-results": {
                "uuid": doc_uuid,
                "metadata": _build_metadata(
                    f"Warlock GRC Assessment Results — {system_name}"
                ),
                "import-ap": {"href": "#"},
                "results": oscal_results,
            }
        }

    def _build_result_block(
        self,
        framework: str,
        cr_list: list[ControlResult],
        findings_map: dict[str, Finding],
        system_name: str,
    ) -> dict[str, Any]:
        """Build a single OSCAL result block for one framework."""

        # Derive time range
        starts = [cr.assessed_at for cr in cr_list if cr.assessed_at]
        start_dt = min(starts) if starts else datetime.now(timezone.utc)
        end_dt = max(starts) if starts else datetime.now(timezone.utc)

        # Inventory items + components keyed by resource_id
        inventory_items: list[dict[str, Any]] = []
        components: list[dict[str, Any]] = []
        resource_uuid_map: dict[str, str] = {}  # resource_id -> uuid
        seen_resources: set[str] = set()

        # Observations and findings
        observations: list[dict[str, Any]] = []
        oscal_findings: list[dict[str, Any]] = []

        # Unique control IDs for reviewed-controls
        control_ids_seen: set[str] = set()

        for cr in cr_list:
            finding = findings_map.get(cr.finding_id)

            # Build inventory item if we have a resource
            if finding and finding.resource_id and finding.resource_id not in seen_resources:
                seen_resources.add(finding.resource_id)
                res_uuid = _deterministic_uuid("resource", finding.resource_id)
                resource_uuid_map[finding.resource_id] = res_uuid
                inventory_items.append({
                    "uuid": res_uuid,
                    "description": finding.resource_name or finding.resource_id,
                    "props": [
                        p for p in [
                            {"name": "resource-type", "value": finding.resource_type}
                            if finding.resource_type else None,
                            {"name": "account-id", "value": finding.account_id}
                            if finding.account_id else None,
                            {"name": "region", "value": finding.region}
                            if finding.region else None,
                        ] if p is not None
                    ],
                })
                components.append({
                    "uuid": _deterministic_uuid("component", finding.resource_id),
                    "type": "this-system",
                    "title": finding.resource_name or finding.resource_type or "Unknown",
                    "description": f"Resource {finding.resource_id}",
                    "status": {"state": "operational"},
                })

            # Build observation
            obs_uuid = _deterministic_uuid("observation", cr.id)
            obs: dict[str, Any] = {
                "uuid": obs_uuid,
                "title": finding.title if finding else f"Observation for {cr.control_id}",
                "description": (
                    json.dumps(finding.detail) if finding and isinstance(finding.detail, (dict, list))
                    else str(finding.detail) if finding and finding.detail
                    else f"Assessment observation for control {cr.control_id}"
                ),
                "methods": ["TEST"],
                "types": ["finding"],
                "collected": _iso(finding.observed_at if finding else cr.assessed_at),
                "props": [
                    {"name": "severity", "value": _severity_to_oscal(cr.severity)},
                ],
            }
            if finding:
                obs["props"].append({"name": "source", "value": finding.provider})
                obs["props"].append(
                    {"name": "observation-type", "value": finding.observation_type}
                )
                if finding.resource_id and finding.resource_id in resource_uuid_map:
                    obs["subjects"] = [
                        {
                            "subject-uuid": resource_uuid_map[finding.resource_id],
                            "type": "inventory-item",
                        }
                    ]
            observations.append(obs)

            # Build OSCAL finding
            oscal_ctrl = _oscal_control_id(framework, cr.control_id)
            control_ids_seen.add(oscal_ctrl)

            finding_uuid = _deterministic_uuid("finding", cr.id)
            method = "ai" if cr.ai_assessment else "assertion"
            oscal_finding: dict[str, Any] = {
                "uuid": finding_uuid,
                "title": f"{cr.control_id} Assessment",
                "description": (
                    cr.ai_assessment
                    or (json.dumps(cr.assertion_findings) if cr.assertion_findings else "")
                    or f"Automated assessment of {cr.control_id}"
                ),
                "target": {
                    "type": "objective-id",
                    "target-id": oscal_ctrl,
                    "status": {"state": _status_to_oscal(cr.status)},
                    "props": [
                        {"name": "assessment-method", "value": method},
                    ],
                },
                "related-observations": [{"observation-uuid": obs_uuid}],
                "props": [
                    {"name": "framework", "value": framework},
                    {"name": "assessor", "value": cr.assessor or "unknown"},
                ],
            }
            if cr.ai_confidence is not None:
                oscal_finding["props"].append(
                    {"name": "ai-confidence", "value": str(cr.ai_confidence)}
                )
            oscal_findings.append(oscal_finding)

        result_block: dict[str, Any] = {
            "uuid": str(uuid4()),
            "title": f"Automated Assessment — {framework}",
            "description": f"Warlock automated assessment results for {framework} on {system_name}",
            "start": _iso(start_dt),
            "end": _iso(end_dt),
            "reviewed-controls": {
                "control-selections": [
                    {
                        "include-controls": [
                            {"control-id": cid} for cid in sorted(control_ids_seen)
                        ]
                    }
                ]
            },
            "observations": observations,
            "findings": oscal_findings,
        }

        if inventory_items or components:
            result_block["local-definitions"] = {}
            if inventory_items:
                result_block["local-definitions"]["inventory-items"] = inventory_items
            if components:
                result_block["local-definitions"]["components"] = components

        return result_block

    # ------------------------------------------------------------------
    # System Security Plan
    # ------------------------------------------------------------------

    def export_ssp(
        self,
        session: Session,
        framework: str,
        system_name: str,
        description: str,
        narrator: Any | None = None,
    ) -> dict[str, Any]:
        """Export an OSCAL System Security Plan.

        When ``narrator`` (an ``AINarrator``) is provided, each control gets
        an AI-generated implementation narrative in the appropriate framework
        voice — making this useful for ISO SoAs, SOC 2 descriptions, etc.,
        not just NIST SSPs.

        Args:
            session: SQLAlchemy session.
            framework: The framework to build the SSP for.
            system_name: Human-readable system name.
            description: System description text.
            narrator: Optional AINarrator for AI-enriched narratives.

        Returns:
            Complete OSCAL system-security-plan dict.
        """
        # Query all control results for this framework
        cr_rows: list[ControlResult] = (
            session.query(ControlResult)
            .filter(ControlResult.framework == framework)
            .all()
        )

        # Gather related findings for inventory
        finding_ids = {cr.finding_id for cr in cr_rows}
        findings_map: dict[str, Finding] = {}
        if finding_ids:
            for f in session.query(Finding).filter(Finding.id.in_(finding_ids)).all():
                findings_map[f.id] = f

        # Build components and inventory from findings
        components: list[dict[str, Any]] = []
        inventory_items: list[dict[str, Any]] = []
        seen_resources: set[str] = set()

        for cr in cr_rows:
            finding = findings_map.get(cr.finding_id)
            if finding and finding.resource_id and finding.resource_id not in seen_resources:
                seen_resources.add(finding.resource_id)
                res_uuid = _deterministic_uuid("resource", finding.resource_id)
                components.append({
                    "uuid": _deterministic_uuid("component", finding.resource_id),
                    "type": "this-system",
                    "title": finding.resource_name or finding.resource_type or "Unknown",
                    "description": f"Resource {finding.resource_id}",
                    "status": {"state": "operational"},
                })
                inv_props = [
                    p for p in [
                        {"name": "resource-type", "value": finding.resource_type}
                        if finding.resource_type else None,
                        {"name": "account-id", "value": finding.account_id}
                        if finding.account_id else None,
                        {"name": "region", "value": finding.region}
                        if finding.region else None,
                    ] if p is not None
                ]
                inventory_items.append({
                    "uuid": res_uuid,
                    "description": finding.resource_name or finding.resource_id,
                    "props": inv_props,
                    "implemented-components": [
                        {
                            "component-uuid": _deterministic_uuid(
                                "component", finding.resource_id
                            )
                        }
                    ],
                })

        # Aggregate control results to per-control implementation status.
        ctrl_statuses: dict[str, list[str]] = {}
        ctrl_details: dict[str, list[ControlResult]] = {}
        # Track original (non-lowered) control IDs for narrator lookup
        ctrl_original_ids: dict[str, str] = {}
        for cr in cr_rows:
            oscal_ctrl = _oscal_control_id(framework, cr.control_id)
            ctrl_statuses.setdefault(oscal_ctrl, []).append(cr.status)
            ctrl_details.setdefault(oscal_ctrl, []).append(cr)
            ctrl_original_ids[oscal_ctrl] = cr.control_id

        implemented_requirements: list[dict[str, Any]] = []
        for ctrl_id in sorted(ctrl_statuses.keys()):
            statuses = ctrl_statuses[ctrl_id]
            crs = ctrl_details[ctrl_id]
            agg_status = self._aggregate_impl_status(statuses)
            original_ctrl = ctrl_original_ids.get(ctrl_id, ctrl_id)

            # --- AI narrative generation (if narrator available) ---
            ai_narrative = None
            if narrator is not None:
                try:
                    from warlock.assessors.ai_narrator import aggregate_control_evidence
                    evidence = aggregate_control_evidence(session, framework, original_ctrl)
                    if evidence.findings:
                        ai_narrative = narrator.generate_implementation(evidence)
                        log.info(
                            "AI narrative generated for %s/%s (confidence=%.2f)",
                            framework, original_ctrl, ai_narrative.confidence,
                        )
                except Exception:
                    log.exception("AI narrative failed for %s/%s", framework, original_ctrl)

            # Build the implementation description
            if ai_narrative and ai_narrative.narrative:
                # Use the AI-generated narrative as the primary description
                impl_description = ai_narrative.narrative
                status_text = ai_narrative.status_summary
            else:
                # Fallback: synthesize from raw assessment data
                impl_description = self._synthesize_impl_description(crs, agg_status)
                status_text = ""

            # Build statements from individual results
            statements: list[dict[str, Any]] = []
            if ai_narrative and ai_narrative.narrative:
                # Single cohesive statement from AI
                statements.append({
                    "statement-id": f"{ctrl_id}_stmt.narrative",
                    "uuid": _deterministic_uuid("ssp-stmt-ai", f"{framework}|{ctrl_id}"),
                    "description": impl_description,
                })
                # Add evidence summary as a separate statement
                if ai_narrative.evidence_summary:
                    statements.append({
                        "statement-id": f"{ctrl_id}_stmt.evidence",
                        "uuid": _deterministic_uuid("ssp-stmt-ev", f"{framework}|{ctrl_id}"),
                        "description": f"Evidence: {ai_narrative.evidence_summary}",
                    })
            else:
                for cr in crs:
                    stmt_text = cr.ai_assessment or cr.remediation_summary or f"Assessment by {cr.assessor}"
                    statements.append({
                        "statement-id": f"{ctrl_id}_stmt.{_deterministic_uuid('stmt', cr.id)[:8]}",
                        "uuid": _deterministic_uuid("ssp-stmt", cr.id),
                        "description": stmt_text,
                    })

            req: dict[str, Any] = {
                "uuid": _deterministic_uuid("ssp-req", f"{framework}|{ctrl_id}"),
                "control-id": ctrl_id,
                "props": [
                    {"name": "implementation-status", "value": agg_status},
                ],
            }
            if status_text:
                req["props"].append({"name": "status-summary", "value": status_text})
            if ai_narrative:
                req["props"].append({"name": "narrative-model", "value": ai_narrative.model})
                req["props"].append({"name": "narrative-confidence", "value": str(ai_narrative.confidence)})
                if ai_narrative.gaps:
                    for gap in ai_narrative.gaps:
                        req["props"].append({"name": "gap", "value": gap})
            if statements:
                req["statements"] = statements
            implemented_requirements.append(req)

        profile_href = (
            _load_local_catalog(framework)
            or _FRAMEWORK_PROFILE_URIS.get(framework, f"#{framework}-profile")
        )

        return {
            "system-security-plan": {
                "uuid": str(uuid4()),
                "metadata": _build_metadata(
                    f"Warlock GRC SSP — {system_name}"
                ),
                "import-profile": {"href": profile_href},
                "system-characteristics": {
                    "system-name": system_name,
                    "system-ids": [
                        {
                            "identifier-type": "https://warlock.dev",
                            "identifier": _deterministic_uuid("system", system_name),
                        }
                    ],
                    "description": description,
                    "security-sensitivity-level": "moderate",
                    "system-information": {
                        "information-types": [
                            {
                                "uuid": _deterministic_uuid("infotype", system_name),
                                "title": "System Information",
                                "description": f"Information processed by {system_name}",
                                "categorizations": [
                                    {
                                        "system": "https://doi.org/10.6028/NIST.SP.800-60v2r1",
                                        "information-type-ids": ["C.3.5.8"],
                                    }
                                ],
                                "confidentiality-impact": {"base": "moderate"},
                                "integrity-impact": {"base": "moderate"},
                                "availability-impact": {"base": "moderate"},
                            }
                        ]
                    },
                    "authorization-boundary": {
                        "description": f"Authorization boundary for {system_name} as assessed by Warlock GRC."
                    },
                },
                "system-implementation": {
                    "users": [
                        {
                            "uuid": _deterministic_uuid("user", "warlock-assessor"),
                            "title": "Warlock Automated Assessor",
                            "role-ids": ["assessor"],
                        }
                    ],
                    "components": components if components else [
                        {
                            "uuid": _deterministic_uuid("component", system_name),
                            "type": "this-system",
                            "title": system_name,
                            "description": description,
                            "status": {"state": "operational"},
                        }
                    ],
                    "inventory-items": inventory_items,
                },
                "control-implementation": {
                    "description": f"Control implementation for {framework} as assessed by Warlock GRC pipeline.",
                    "implemented-requirements": implemented_requirements,
                },
            }
        }

    @staticmethod
    def _aggregate_impl_status(statuses: list[str]) -> str:
        """Aggregate a list of per-finding statuses into one implementation status."""
        status_set = set(statuses)
        if status_set == {"compliant"}:
            return "implemented"
        if status_set == {"not_applicable"}:
            return "not-applicable"
        if "non_compliant" in status_set and "compliant" in status_set:
            return "partial"
        if "non_compliant" in status_set:
            return "planned"
        if "partial" in status_set:
            return "partial"
        if "not_assessed" in status_set:
            return "planned"
        return "implemented"

    @staticmethod
    def _synthesize_impl_description(
        crs: list[ControlResult],
        agg_status: str,
    ) -> str:
        """Build a basic implementation description from raw control results.

        Used as fallback when AI narrator is not available.
        """
        parts: list[str] = []
        assessors = set()
        sources = set()
        for cr in crs:
            if cr.assessor:
                assessors.add(cr.assessor.split(":")[0])
            if cr.assertion_name:
                sources.add(cr.assertion_name)
            if cr.assertion_findings:
                for finding in (cr.assertion_findings if isinstance(cr.assertion_findings, list) else []):
                    parts.append(str(finding))

        status_label = {
            "implemented": "fully implemented",
            "partial": "partially implemented",
            "planned": "not yet implemented (planned)",
            "not-applicable": "not applicable",
        }.get(agg_status, agg_status)

        desc = f"This control is {status_label}."
        if sources:
            desc += f" Assessed via: {', '.join(sorted(sources))}."
        if parts:
            desc += f" Findings: {'; '.join(parts[:5])}"
            if len(parts) > 5:
                desc += f" (+{len(parts) - 5} more)"
            desc += "."
        return desc

    # ------------------------------------------------------------------
    # Plan of Action & Milestones
    # ------------------------------------------------------------------

    def export_poam(
        self,
        session: Session,
        framework: str | None,
        system_name: str,
        narrator: Any | None = None,
    ) -> dict[str, Any]:
        """Export OSCAL Plan of Action and Milestones.

        When ``narrator`` is provided, each POA&M item gets an AI-generated
        remediation plan with framework-appropriate language, risk statements,
        milestones, and estimated effort.

        Args:
            session: SQLAlchemy session.
            framework: Filter to one framework, or ``None`` for all.
            system_name: Human-readable system name.
            narrator: Optional AINarrator for AI-enriched remediation plans.

        Returns:
            Complete OSCAL plan-of-action-and-milestones dict.
        """
        query = session.query(ControlResult).filter(
            ControlResult.status.in_(["non_compliant", "partial"])
        )
        if framework:
            query = query.filter(ControlResult.framework == framework)

        cr_rows: list[ControlResult] = query.all()

        # Pre-fetch findings
        finding_ids = {cr.finding_id for cr in cr_rows}
        findings_map: dict[str, Finding] = {}
        if finding_ids:
            for f in session.query(Finding).filter(Finding.id.in_(finding_ids)).all():
                findings_map[f.id] = f

        # Group by (framework, control_id) for narrator — one remediation
        # plan per control, not per finding
        ctrl_groups: dict[tuple[str, str], list[ControlResult]] = {}
        for cr in cr_rows:
            ctrl_groups.setdefault((cr.framework, cr.control_id), []).append(cr)

        # Generate AI remediation plans per control
        ai_plans: dict[tuple[str, str], Any] = {}
        if narrator is not None:
            from warlock.assessors.ai_narrator import aggregate_control_evidence
            for (fw, ctrl_id), _ in ctrl_groups.items():
                try:
                    evidence = aggregate_control_evidence(session, fw, ctrl_id)
                    if evidence.findings:
                        plan = narrator.generate_remediation(evidence)
                        ai_plans[(fw, ctrl_id)] = plan
                        log.info(
                            "AI remediation plan for %s/%s (priority=%s, confidence=%.2f)",
                            fw, ctrl_id, plan.priority, plan.confidence,
                        )
                except Exception:
                    log.exception("AI remediation failed for %s/%s", fw, ctrl_id)

        poam_items: list[dict[str, Any]] = []
        seen_controls: set[tuple[str, str]] = set()

        for cr in cr_rows:
            finding = findings_map.get(cr.finding_id)
            obs_uuid = _deterministic_uuid("observation", cr.id)
            finding_uuid = _deterministic_uuid("finding", cr.id)

            ctrl_key = (cr.framework, cr.control_id)
            ai_plan = ai_plans.get(ctrl_key)

            # If we have an AI plan and haven't emitted this control yet,
            # use the AI plan as the primary item
            if ai_plan and ctrl_key not in seen_controls:
                seen_controls.add(ctrl_key)

                # Build milestones
                milestones = []
                for ms in ai_plan.milestones:
                    milestones.append({
                        "uuid": _deterministic_uuid("milestone", f"{cr.framework}|{cr.control_id}|{ms.get('title', '')}"),
                        "title": ms.get("title", "Milestone"),
                        "description": ms.get("target_date", ""),
                    })

                # Build remarks from remediation steps
                remarks = ""
                if ai_plan.remediation_steps:
                    remarks = "\n".join(
                        f"{i+1}. {step}" for i, step in enumerate(ai_plan.remediation_steps)
                    )
                if ai_plan.risk_statement:
                    remarks = f"Risk: {ai_plan.risk_statement}\n\n{remarks}" if remarks else f"Risk: {ai_plan.risk_statement}"

                item: dict[str, Any] = {
                    "uuid": _deterministic_uuid("poam-ai", f"{cr.framework}|{cr.control_id}"),
                    "title": ai_plan.title,
                    "description": ai_plan.description,
                    "props": [
                        {"name": "status", "value": "open"},
                        {"name": "severity", "value": _severity_to_oscal(cr.severity)},
                        {"name": "framework", "value": cr.framework},
                        {"name": "control-id", "value": _oscal_control_id(cr.framework, cr.control_id)},
                        {"name": "priority", "value": ai_plan.priority},
                        {"name": "estimated-effort", "value": ai_plan.estimated_effort},
                        {"name": "narrative-model", "value": ai_plan.model},
                        {"name": "narrative-confidence", "value": str(ai_plan.confidence)},
                    ],
                    "related-observations": [{"observation-uuid": obs_uuid}],
                    "related-findings": [{"finding-uuid": finding_uuid}],
                }
                if remarks:
                    item["remarks"] = remarks
                if milestones:
                    item["milestones"] = milestones
                if finding:
                    item["props"].append({"name": "resource-id", "value": finding.resource_id or "unknown"})

                poam_items.append(item)
            elif ctrl_key in seen_controls:
                # Already emitted an AI-enriched item for this control; skip
                # individual findings to avoid duplication
                continue
            else:
                # No AI — use the existing deterministic output
                remarks = ""
                if cr.remediation_steps:
                    if isinstance(cr.remediation_steps, list):
                        remarks = "\n".join(
                            f"{i+1}. {step}" if isinstance(step, str) else f"{i+1}. {json.dumps(step)}"
                            for i, step in enumerate(cr.remediation_steps)
                        )
                    else:
                        remarks = str(cr.remediation_steps)

                item = {
                    "uuid": _deterministic_uuid("poam", cr.id),
                    "title": cr.remediation_summary or f"Remediation required for {cr.control_id}",
                    "description": (
                        cr.ai_assessment
                        or (
                            json.dumps(cr.assertion_findings)
                            if cr.assertion_findings
                            else f"Non-compliant finding for {cr.control_id} in {cr.framework}"
                        )
                    ),
                    "props": [
                        {"name": "status", "value": "open"},
                        {"name": "severity", "value": _severity_to_oscal(cr.severity)},
                        {"name": "framework", "value": cr.framework},
                        {"name": "control-id", "value": _oscal_control_id(cr.framework, cr.control_id)},
                    ],
                    "related-observations": [{"observation-uuid": obs_uuid}],
                    "related-findings": [{"finding-uuid": finding_uuid}],
                }

                if remarks:
                    item["remarks"] = remarks
                if cr.console_path:
                    item["props"].append({"name": "console-path", "value": cr.console_path})
                if finding:
                    item["props"].append({"name": "resource-id", "value": finding.resource_id or "unknown"})

                poam_items.append(item)

        return {
            "plan-of-action-and-milestones": {
                "uuid": str(uuid4()),
                "metadata": _build_metadata(
                    f"Warlock GRC POA&M — {system_name}"
                ),
                "import-ssp": {"href": "#"},
                "poam-items": poam_items,
            }
        }

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def to_json(data: dict[str, Any], pretty: bool = True) -> str:
        """Serialise OSCAL dict to JSON string.

        Args:
            data: An OSCAL document dict.
            pretty: If ``True``, indent with 2 spaces.

        Returns:
            JSON string.
        """
        return json.dumps(data, indent=2 if pretty else None, default=str)

    @staticmethod
    def to_file(data: dict[str, Any], path: str) -> None:
        """Write OSCAL dict to a JSON file.

        Parent directories are created automatically.

        Args:
            data: An OSCAL document dict.
            path: Destination file path.
        """
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        log.info("OSCAL document written to %s", dest)
