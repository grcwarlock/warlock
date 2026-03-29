"""OSCAL Assessment Plan (SAP) export for Warlock GRC pipeline.

Produces a valid OSCAL assessment-plan JSON document conforming to
NIST OSCAL 1.1.2.  The SAP describes *what* will be assessed, *how*,
and *when* -- it is the companion to assessment-results (what was found).

Used in audit packages and FedRAMP authorization workflows.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4, uuid5

from sqlalchemy.orm import Session

from warlock.db.models import ControlResult
from warlock.export.oscal import (
    WARLOCK_NS,
    _build_metadata,
    _deterministic_uuid,
    _oscal_control_id,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Assessment activity descriptions per method type
# ---------------------------------------------------------------------------

_ACTIVITY_DESCRIPTIONS: dict[str, str] = {
    "TEST": (
        "Automated technical testing of control implementation via "
        "evidence collection, policy-as-code assertions, and "
        "configuration validation."
    ),
    "EXAMINE": (
        "Examination of documentation, policies, procedures, and "
        "configuration artifacts to verify control design and intent."
    ),
    "INTERVIEW": (
        "AI-assisted reasoning over collected evidence to evaluate "
        "control effectiveness, simulating expert interview analysis."
    ),
}


class OscalSapExporter:
    """Produces OSCAL Assessment Plan JSON from the Warlock pipeline database."""

    def export_sap(
        self,
        session: Session,
        framework: str,
        system_name: str,
        *,
        assessment_title: str | None = None,
        assessment_days: int = 30,
    ) -> dict[str, Any]:
        """Export an OSCAL Assessment Plan document.

        Args:
            session: SQLAlchemy session.
            framework: The framework to build the SAP for.
            system_name: Human-readable system name.
            assessment_title: Optional custom title for the assessment.
            assessment_days: Duration of the assessment window in days.

        Returns:
            Complete OSCAL assessment-plan dict ready for serialisation.
        """
        cr_rows: list[ControlResult] = (
            session.query(ControlResult).filter(ControlResult.framework == framework).all()
        )

        # Collect unique control IDs and assessment methods used
        control_ids: set[str] = set()
        methods_used: set[str] = set()
        assessors_seen: set[str] = set()
        for cr in cr_rows:
            control_ids.add(_oscal_control_id(framework, cr.control_id))
            if cr.ai_assessment:
                methods_used.add("INTERVIEW")
            else:
                methods_used.add("TEST")
            if cr.assessor:
                assessors_seen.add(cr.assessor.split(":")[0])

        # Default to TEST if no results yet
        if not methods_used:
            methods_used.add("TEST")

        now = datetime.now(timezone.utc)
        start_date = now
        end_date = now + timedelta(days=assessment_days)
        title = assessment_title or (f"Warlock GRC Assessment Plan -- {system_name} ({framework})")

        warlock_party_uuid = str(uuid5(WARLOCK_NS, "warlock-grc"))

        # Build assessment activities
        activities: list[dict[str, Any]] = []
        for method in sorted(methods_used):
            act_uuid = _deterministic_uuid("sap-activity", f"{framework}|{method}")
            activities.append(
                {
                    "uuid": act_uuid,
                    "title": f"{method.title()} Assessment",
                    "description": _ACTIVITY_DESCRIPTIONS.get(
                        method,
                        f"Assessment activity using {method} method.",
                    ),
                    "props": [
                        {"name": "method", "value": method},
                    ],
                    "related-controls": {
                        "control-selections": [
                            {
                                "include-controls": [
                                    {"control-id": cid} for cid in sorted(control_ids)
                                ]
                            }
                        ]
                    },
                    "responsible-roles": [
                        {
                            "role-id": "assessor",
                            "party-uuids": [warlock_party_uuid],
                        }
                    ],
                }
            )

        # Build assessment subjects
        subjects: list[dict[str, Any]] = [
            {
                "type": "this-system",
                "description": (
                    f"The {system_name} system and its components as assessed against {framework}."
                ),
                "include-all": {},
            }
        ]

        # Build the SAP terms / schedule
        schedule: dict[str, Any] = {
            "tasks": [
                {
                    "uuid": _deterministic_uuid("sap-task", f"{framework}|evidence-collection"),
                    "type": "action",
                    "title": "Evidence Collection",
                    "description": (
                        "Collect evidence from connected sources via "
                        "Warlock connectors and normalizers."
                    ),
                    "timing": {
                        "within-date-range": {
                            "start": start_date.isoformat(),
                            "end": end_date.isoformat(),
                        }
                    },
                },
                {
                    "uuid": _deterministic_uuid("sap-task", f"{framework}|control-assessment"),
                    "type": "action",
                    "title": "Control Assessment",
                    "description": (
                        "Evaluate collected evidence against control "
                        "requirements using assertion engine and "
                        "AI-assisted reasoning."
                    ),
                    "timing": {
                        "within-date-range": {
                            "start": start_date.isoformat(),
                            "end": end_date.isoformat(),
                        }
                    },
                },
                {
                    "uuid": _deterministic_uuid("sap-task", f"{framework}|report-generation"),
                    "type": "action",
                    "title": "Report Generation",
                    "description": (
                        "Generate OSCAL assessment results, SSP, and "
                        "POA&M documents from assessment findings."
                    ),
                    "timing": {
                        "within-date-range": {
                            "start": end_date.isoformat(),
                            "end": (end_date + timedelta(days=7)).isoformat(),
                        }
                    },
                },
            ]
        }

        # Reviewed controls
        reviewed_controls: dict[str, Any] = {
            "control-selections": [
                {"include-controls": [{"control-id": cid} for cid in sorted(control_ids)]}
            ]
        }

        metadata = _build_metadata(title)

        doc: dict[str, Any] = {
            "assessment-plan": {
                "uuid": str(uuid4()),
                "metadata": metadata,
                "import-ssp": {
                    "href": f"./ssp-{framework}.json",
                },
                "local-definitions": {
                    "activities": activities,
                },
                "terms-and-conditions": {
                    "parts": [
                        {
                            "name": "assessment-scope",
                            "prose": (
                                f"This assessment covers the {framework} "
                                f"framework controls for {system_name}. "
                                "Evidence is collected via automated "
                                "connectors and assessed using policy-as-code "
                                "assertions and AI-assisted reasoning."
                            ),
                        },
                    ]
                },
                "reviewed-controls": reviewed_controls,
                "assessment-subjects": subjects,
                "tasks": schedule["tasks"],
                "responsible-parties": [
                    {
                        "role-id": "assessor",
                        "party-uuids": [warlock_party_uuid],
                    },
                    {
                        "role-id": "tool",
                        "party-uuids": [warlock_party_uuid],
                    },
                ],
            }
        }

        return doc

    @staticmethod
    def to_json(data: dict[str, Any], pretty: bool = True) -> str:
        """Serialise OSCAL SAP dict to JSON string."""
        return json.dumps(data, indent=2 if pretty else None, default=str)

    @staticmethod
    def to_file(data: dict[str, Any], path: str) -> None:
        """Write OSCAL SAP dict to a JSON file."""
        from pathlib import Path

        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        log.info("OSCAL SAP document written to %s", dest)
