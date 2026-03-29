"""SSP narrative generation for Warlock GRC platform.

Generates human-readable System Security Plan narratives from OSCAL SSP
data.  Output is Markdown suitable for conversion to PDF via existing
reportlab/weasyprint tooling.

Supports two modes:
- **Static**: Synthesises narratives from assessment data (default).
- **AI-assisted**: Uses the AINarrator to generate prose for each control
  implementation statement (guarded by WLK_AI_ENABLED).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from warlock.export.oscal import (
    OscalExporter,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _status_label(impl_status: str) -> str:
    """Human-readable label for an OSCAL implementation-status value."""
    return {
        "implemented": "Fully Implemented",
        "partial": "Partially Implemented",
        "planned": "Planned",
        "alternative": "Alternative Implementation",
        "not-applicable": "Not Applicable",
    }.get(impl_status, impl_status.replace("-", " ").title())


def _severity_icon(severity: str) -> str:
    """Return a text marker for severity level."""
    return {
        "critical": "[CRITICAL]",
        "high": "[HIGH]",
        "medium": "[MEDIUM]",
        "moderate": "[MODERATE]",
        "low": "[LOW]",
        "info": "[INFO]",
    }.get(severity.lower() if severity else "", "")


# ---------------------------------------------------------------------------
# Narrative generator
# ---------------------------------------------------------------------------


class SspNarrativeGenerator:
    """Generate a Markdown SSP narrative from database assessment data."""

    def generate(
        self,
        session: Session,
        framework: str,
        system_name: str,
        description: str = "",
        *,
        ai_mode: bool = False,
    ) -> str:
        """Generate a Markdown SSP narrative.

        Args:
            session: SQLAlchemy session.
            framework: Framework slug (e.g. 'soc2', 'nist_800_53').
            system_name: Human-readable system name.
            description: System description text.
            ai_mode: If True and WLK_AI_ENABLED, use AI for prose.

        Returns:
            Markdown string containing the full SSP narrative.
        """
        # First, generate the OSCAL SSP to get structured data
        exporter = OscalExporter()
        narrator = None

        if ai_mode:
            narrator = self._get_narrator()

        ssp_data = exporter.export_ssp(
            session,
            framework=framework,
            system_name=system_name,
            description=description or f"{system_name} System Security Plan",
            narrator=narrator,
        )

        ssp = ssp_data.get("system-security-plan", {})
        return self._render_markdown(ssp, framework, system_name, description)

    @staticmethod
    def _get_narrator() -> Any:
        """Attempt to create an AI narrator, returning None if unavailable."""
        from warlock.config import get_settings

        settings = get_settings()
        if not settings.ai_enabled:
            log.info("AI mode requested but WLK_AI_ENABLED=false; using static")
            return None
        try:
            from warlock.assessors.ai_narrator import create_narrator

            return create_narrator()
        except Exception:
            log.warning("Could not create AI narrator; falling back to static")
            return None

    def _render_markdown(
        self,
        ssp: dict[str, Any],
        framework: str,
        system_name: str,
        description: str,
    ) -> str:
        """Render OSCAL SSP dict to Markdown."""
        lines: list[str] = []
        meta = ssp.get("metadata", {})
        chars = ssp.get("system-characteristics", {})
        impl = ssp.get("system-implementation", {})
        ctrl_impl = ssp.get("control-implementation", {})

        # Title page
        lines.append(f"# System Security Plan: {system_name}")
        lines.append("")
        lines.append(f"**Framework:** {framework}")
        lines.append(f"**Version:** {meta.get('version', '1.0.0')}")
        lines.append(f"**Last Modified:** {meta.get('last-modified', 'N/A')}")
        lines.append(f"**OSCAL Version:** {meta.get('oscal-version', 'N/A')}")
        lines.append("")

        # Parties
        parties = meta.get("parties", [])
        if parties:
            lines.append("**Prepared by:**")
            for party in parties:
                lines.append(f"- {party.get('name', 'Unknown')}")
            lines.append("")

        lines.append("---")
        lines.append("")

        # 1. System Description
        lines.append("## 1. System Description")
        lines.append("")
        lines.append(description or chars.get("description", f"{system_name} system."))
        lines.append("")

        # System IDs
        sys_ids = chars.get("system-ids", [])
        if sys_ids:
            lines.append("**System Identifiers:**")
            for sid in sys_ids:
                lines.append(
                    f"- Type: `{sid.get('identifier-type', '')}` ID: `{sid.get('identifier', '')}`"
                )
            lines.append("")

        # 2. Authorization Boundary
        lines.append("## 2. Authorization Boundary")
        lines.append("")
        boundary = chars.get("authorization-boundary", {})
        lines.append(
            boundary.get(
                "description",
                f"The authorization boundary encompasses all components of {system_name}.",
            )
        )
        lines.append("")

        # 3. Security Categorization
        lines.append("## 3. Security Categorization")
        lines.append("")
        sens = chars.get("security-sensitivity-level", "moderate")
        lines.append(f"**Security Sensitivity Level:** {sens.title()}")
        lines.append("")

        impact = chars.get("security-impact-level", {})
        if impact:
            lines.append("| Objective | Level |")
            lines.append("|---|---|")
            lines.append(
                f"| Confidentiality | "
                f"{impact.get('security-objective-confidentiality', 'N/A').title()} |"
            )
            lines.append(
                f"| Integrity | {impact.get('security-objective-integrity', 'N/A').title()} |"
            )
            lines.append(
                f"| Availability | {impact.get('security-objective-availability', 'N/A').title()} |"
            )
            lines.append("")

        # Status and date authorized
        status = chars.get("status", {})
        if status:
            lines.append(f"**System Status:** {status.get('state', 'N/A').title()}")
        date_auth = chars.get("date-authorized")
        if date_auth:
            lines.append(f"**Date Authorized:** {date_auth}")
        lines.append("")

        # 4. Information Types
        lines.append("## 4. Information Types")
        lines.append("")
        info_types = chars.get("system-information", {}).get("information-types", [])
        for it in info_types:
            lines.append(f"### {it.get('title', 'Unknown')}")
            lines.append("")
            lines.append(it.get("description", ""))
            lines.append("")
            c_impact = it.get("confidentiality-impact", {})
            i_impact = it.get("integrity-impact", {})
            a_impact = it.get("availability-impact", {})
            if c_impact or i_impact or a_impact:
                lines.append("| Impact Category | Base Level |")
                lines.append("|---|---|")
                if c_impact:
                    lines.append(f"| Confidentiality | {c_impact.get('base', 'N/A').title()} |")
                if i_impact:
                    lines.append(f"| Integrity | {i_impact.get('base', 'N/A').title()} |")
                if a_impact:
                    lines.append(f"| Availability | {a_impact.get('base', 'N/A').title()} |")
                lines.append("")

        # 5. System Components
        lines.append("## 5. System Components")
        lines.append("")
        components = impl.get("components", [])
        if components:
            lines.append(f"The system comprises {len(components)} component(s):")
            lines.append("")
            lines.append("| Component | Type | Status |")
            lines.append("|---|---|---|")
            for comp in components[:50]:  # Cap display
                title = comp.get("title", "Unknown")
                ctype = comp.get("type", "unknown")
                cstatus = comp.get("status", {}).get("state", "unknown")
                lines.append(f"| {title} | {ctype} | {cstatus} |")
            if len(components) > 50:
                lines.append(f"| ... | ({len(components) - 50} more) | |")
            lines.append("")
        else:
            lines.append("No components defined.")
            lines.append("")

        # 6. Users
        lines.append("## 6. System Users")
        lines.append("")
        users = impl.get("users", [])
        if users:
            for user in users:
                roles = ", ".join(user.get("role-ids", []))
                lines.append(f"- **{user.get('title', 'Unknown')}** ({roles})")
            lines.append("")

        # 7. Responsible Parties
        lines.append("## 7. Responsible Parties")
        lines.append("")
        rps = ssp.get("responsible-parties", [])
        if rps:
            for rp in rps:
                role = rp.get("role-id", "unknown")
                party_ids = rp.get("party-uuids", [])
                lines.append(f"- **{role}**: {len(party_ids)} party(ies)")
            lines.append("")

        # 8. Control Implementations
        lines.append("## 8. Control Implementation Details")
        lines.append("")
        lines.append(ctrl_impl.get("description", ""))
        lines.append("")

        reqs = ctrl_impl.get("implemented-requirements", [])
        if reqs:
            # Summary table
            status_counts: dict[str, int] = {}
            for req in reqs:
                props = {p["name"]: p["value"] for p in req.get("props", [])}
                s = props.get("implementation-status", "unknown")
                status_counts[s] = status_counts.get(s, 0) + 1

            lines.append("### Implementation Summary")
            lines.append("")
            lines.append("| Status | Count |")
            lines.append("|---|---|")
            for s, c in sorted(status_counts.items()):
                lines.append(f"| {_status_label(s)} | {c} |")
            lines.append(f"| **Total** | **{len(reqs)}** |")
            lines.append("")

            # Per-control details
            lines.append("### Control Details")
            lines.append("")
            for req in reqs:
                ctrl_id = req.get("control-id", "unknown")
                props = {p["name"]: p["value"] for p in req.get("props", [])}
                impl_status = props.get("implementation-status", "unknown")

                lines.append(f"#### {ctrl_id.upper()} -- {_status_label(impl_status)}")
                lines.append("")

                # Statements
                statements = req.get("statements", [])
                for stmt in statements:
                    desc = stmt.get("description", "")
                    if desc:
                        lines.append(desc)
                        lines.append("")

                # Gaps
                gaps = [p["value"] for p in req.get("props", []) if p["name"] == "gap"]
                if gaps:
                    lines.append("**Identified Gaps:**")
                    for gap in gaps:
                        lines.append(f"- {gap}")
                    lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            "*Generated by Warlock GRC Platform. "
            "This document should be reviewed by authorized personnel "
            "before submission to assessors.*"
        )
        lines.append("")

        return "\n".join(lines)
