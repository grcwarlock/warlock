"""Privacy engineering workflows -- data flow diagrams and PIA pre-fill.

Provides:
- ``DataFlowMapper``  -- generates data flow diagrams from data silos and
  system dependency records stored as AuditEntry rows
- ``PIAPrefiller``    -- pre-populates Privacy Impact Assessment templates
  from existing system/data inventory
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data flow diagram structures
# ---------------------------------------------------------------------------


@dataclass
class DataSilo:
    """A system or storage location that holds personal data."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    data_categories: list[str] = field(default_factory=list)
    classification: str = "internal"  # public, internal, confidential, restricted
    location: str = ""  # region / jurisdiction
    retention_days: int = 0
    owner: str = ""


@dataclass
class DataFlow:
    """A data transfer between two silos."""

    source: str = ""
    destination: str = ""
    data_categories: list[str] = field(default_factory=list)
    purpose: str = ""
    legal_basis: str = ""
    cross_border: bool = False
    encrypted: bool = True


@dataclass
class DataFlowDiagram:
    """Complete data flow diagram with silos, flows, and metadata."""

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = "Data Flow Diagram"
    silos: list[DataSilo] = field(default_factory=list)
    flows: list[DataFlow] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    mermaid: str = ""  # Mermaid diagram source

    def to_mermaid(self) -> str:
        """Generate Mermaid flowchart source from silos and flows."""
        lines = ["flowchart LR"]
        silo_ids: dict[str, str] = {}

        for i, silo in enumerate(self.silos):
            sid = f"S{i}"
            silo_ids[silo.name] = sid
            label = f"{silo.name}\\n[{silo.classification}]"
            lines.append(f"    {sid}[{label}]")

        for flow in self.flows:
            src = silo_ids.get(flow.source, flow.source)
            dst = silo_ids.get(flow.destination, flow.destination)
            arrow = "-.->|cross-border|" if flow.cross_border else "-->|"
            purpose = flow.purpose[:30] if flow.purpose else "transfer"
            lines.append(f"    {src} {arrow}{purpose}| {dst}")

        self.mermaid = "\n".join(lines)
        return self.mermaid


# ---------------------------------------------------------------------------
# PIA template
# ---------------------------------------------------------------------------


@dataclass
class PIASection:
    """A section in a Privacy Impact Assessment."""

    title: str = ""
    content: str = ""
    status: str = "draft"  # draft, reviewed, approved


@dataclass
class PIATemplate:
    """Pre-filled Privacy Impact Assessment."""

    id: str = field(default_factory=lambda: str(uuid4()))
    system_name: str = ""
    sections: list[PIASection] = field(default_factory=list)
    risk_level: str = "medium"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# DataFlowMapper
# ---------------------------------------------------------------------------


class DataFlowMapper:
    """Build data flow diagrams from database records."""

    def generate(self, session, system_id: str | None = None) -> DataFlowDiagram:
        """Generate a data flow diagram from AuditEntry records.

        Data silos are stored as AuditEntry(entity_type='data_silo'),
        dependencies as AuditEntry(entity_type='system_dependency').
        """
        from warlock.db.models import AuditEntry

        diagram = DataFlowDiagram()

        # Load data silos
        silo_q = session.query(AuditEntry).filter(AuditEntry.entity_type == "data_silo")
        if system_id:
            silo_q = silo_q.filter(AuditEntry.extra["system_id"].as_string() == system_id)

        silo_entries = silo_q.all()
        for entry in silo_entries:
            extra = entry.extra or {}
            diagram.silos.append(
                DataSilo(
                    id=entry.entity_id,
                    name=extra.get("name", entry.entity_id[:12]),
                    description=extra.get("description", ""),
                    data_categories=extra.get("data_categories", []),
                    classification=extra.get("classification", "internal"),
                    location=extra.get("location", ""),
                    retention_days=extra.get("retention_days", 0),
                    owner=extra.get("owner", ""),
                )
            )

        # Load dependencies as flows
        dep_q = session.query(AuditEntry).filter(AuditEntry.entity_type == "system_dependency")
        dep_entries = dep_q.all()
        for entry in dep_entries:
            extra = entry.extra or {}
            diagram.flows.append(
                DataFlow(
                    source=extra.get("source", ""),
                    destination=extra.get("destination", ""),
                    data_categories=extra.get("data_categories", []),
                    purpose=extra.get("purpose", ""),
                    legal_basis=extra.get("legal_basis", ""),
                    cross_border=extra.get("cross_border", False),
                    encrypted=extra.get("encrypted", True),
                )
            )

        # If no stored data, generate a demo diagram
        if not diagram.silos:
            diagram = self._demo_diagram()

        diagram.to_mermaid()
        return diagram

    @staticmethod
    def _demo_diagram() -> DataFlowDiagram:
        """Generate a demo data flow diagram for showcase."""
        diagram = DataFlowDiagram(title="Demo Data Flow Diagram")
        diagram.silos = [
            DataSilo(
                name="Web App",
                data_categories=["PII", "session"],
                classification="confidential",
                location="US-East",
            ),
            DataSilo(
                name="PostgreSQL",
                data_categories=["PII", "PHI"],
                classification="restricted",
                location="US-East",
            ),
            DataSilo(
                name="S3 Data Lake",
                data_categories=["analytics", "PII"],
                classification="confidential",
                location="US-East",
            ),
            DataSilo(
                name="Analytics (EU)",
                data_categories=["analytics"],
                classification="internal",
                location="EU-West",
            ),
        ]
        diagram.flows = [
            DataFlow(
                source="Web App",
                destination="PostgreSQL",
                data_categories=["PII"],
                purpose="user data storage",
                legal_basis="contract",
            ),
            DataFlow(
                source="PostgreSQL",
                destination="S3 Data Lake",
                data_categories=["PII", "analytics"],
                purpose="backup and analytics",
                legal_basis="legitimate interest",
            ),
            DataFlow(
                source="S3 Data Lake",
                destination="Analytics (EU)",
                data_categories=["analytics"],
                purpose="business intelligence",
                legal_basis="legitimate interest",
                cross_border=True,
            ),
        ]
        return diagram


# ---------------------------------------------------------------------------
# PIAPrefiller
# ---------------------------------------------------------------------------


class PIAPrefiller:
    """Pre-fill a Privacy Impact Assessment template from system data."""

    def prefill(
        self,
        session,
        system_name: str,
        data_categories: list[str] | None = None,
    ) -> PIATemplate:
        """Generate a pre-filled PIA for a named system."""
        # Attempt to load system profile
        system_info = self._load_system_info(session, system_name)
        categories = data_categories or system_info.get("data_categories", ["PII"])

        # Determine risk level from data categories
        risk_level = (
            "high"
            if any(c in categories for c in ["PHI", "PCI", "biometric", "genetic"])
            else "medium"
            if "PII" in categories
            else "low"
        )

        sections = [
            PIASection(
                title="1. System Description",
                content=(
                    f"System: {system_name}\n"
                    f"Description: {system_info.get('description', 'To be completed')}\n"
                    f"Owner: {system_info.get('owner', 'To be assigned')}\n"
                    f"Data categories: {', '.join(categories)}"
                ),
            ),
            PIASection(
                title="2. Data Collection",
                content=(
                    f"Data categories processed: {', '.join(categories)}\n"
                    "Collection method: [To be completed]\n"
                    "Data subjects: [To be completed]\n"
                    "Volume estimate: [To be completed]"
                ),
            ),
            PIASection(
                title="3. Legal Basis",
                content=(
                    "Legal basis for processing: [To be completed]\n"
                    "Consent mechanism: [If applicable]\n"
                    "Legitimate interest assessment: [If applicable]"
                ),
            ),
            PIASection(
                title="4. Data Sharing and Transfers",
                content=(
                    "Third parties: [To be completed]\n"
                    "Cross-border transfers: [To be completed]\n"
                    "Transfer mechanism (SCCs/adequacy): [If applicable]"
                ),
            ),
            PIASection(
                title="5. Security Measures",
                content=(
                    "Encryption at rest: [To be completed]\n"
                    "Encryption in transit: [To be completed]\n"
                    "Access controls: [To be completed]\n"
                    "Audit logging: [To be completed]"
                ),
            ),
            PIASection(
                title="6. Data Subject Rights",
                content=(
                    "Access request process: [To be completed]\n"
                    "Deletion process: [To be completed]\n"
                    "Portability: [To be completed]\n"
                    "Rectification: [To be completed]"
                ),
            ),
            PIASection(
                title="7. Risk Assessment",
                content=(
                    f"Overall risk level: {risk_level}\n"
                    "Identified risks: [To be completed]\n"
                    "Mitigations: [To be completed]"
                ),
            ),
            PIASection(
                title="8. Retention",
                content=(
                    "Retention period: [To be completed]\n"
                    "Deletion mechanism: [To be completed]\n"
                    "Legal hold process: [To be completed]"
                ),
            ),
        ]

        return PIATemplate(
            system_name=system_name,
            sections=sections,
            risk_level=risk_level,
        )

    @staticmethod
    def _load_system_info(session, system_name: str) -> dict[str, Any]:
        """Try to load system info from SystemProfile."""
        try:
            from warlock.db.models import SystemProfile

            sp = (
                session.query(SystemProfile)
                .filter(SystemProfile.name.ilike(f"%{system_name}%"))
                .first()
            )
            if sp:
                return {
                    "description": sp.description or "",
                    "owner": sp.owner or "",
                    "data_categories": ["PII"],
                }
        except Exception:
            pass
        return {}
