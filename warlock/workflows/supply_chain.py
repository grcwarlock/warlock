"""Supply chain compliance workflows.

SBOM ingestion (CycloneDX/SPDX format parsing), component-to-vulnerability
mapping, and supplier compliance inheritance tracking.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class SBOMComponent:
    """A single component from an SBOM."""

    name: str
    version: str = ""
    purl: str = ""
    supplier: str = ""
    licenses: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SBOMAnalysis:
    """Results of SBOM analysis."""

    format: str = ""  # "cyclonedx" or "spdx"
    spec_version: str = ""
    total_components: int = 0
    components: list[SBOMComponent] = field(default_factory=list)
    vulnerable_components: int = 0
    license_risks: list[dict[str, Any]] = field(default_factory=list)
    supplier_coverage: float = 0.0


def parse_cyclonedx(data: dict[str, Any]) -> SBOMAnalysis:
    """Parse a CycloneDX SBOM JSON document.

    Parameters
    ----------
    data: parsed JSON of a CycloneDX BOM
    """
    analysis = SBOMAnalysis(format="cyclonedx")
    analysis.spec_version = data.get("specVersion", data.get("bomFormat", ""))

    components_raw = data.get("components", [])
    analysis.total_components = len(components_raw)

    suppliers_present = 0
    for comp in components_raw:
        c = SBOMComponent(
            name=comp.get("name", "unknown"),
            version=comp.get("version", ""),
            purl=comp.get("purl", ""),
        )
        supplier = comp.get("supplier", {})
        if supplier:
            c.supplier = supplier.get("name", "")
            suppliers_present += 1

        for lic in comp.get("licenses", []):
            if isinstance(lic, dict):
                lid = lic.get("license", {}).get("id", "")
                if lid:
                    c.licenses.append(lid)

        for h in comp.get("hashes", []):
            if isinstance(h, dict):
                c.hashes[h.get("alg", "")] = h.get("content", "")

        analysis.components.append(c)

    # Vulnerability mapping from CycloneDX vulnerabilities section
    for vuln in data.get("vulnerabilities", []):
        vuln_id = vuln.get("id", "")
        severity = ""
        for rating in vuln.get("ratings", []):
            severity = rating.get("severity", severity)
        affected = vuln.get("affects", [])
        for affect in affected:
            ref = affect.get("ref", "")
            for comp in analysis.components:
                if comp.purl == ref or comp.name in ref:
                    comp.vulnerabilities.append(
                        {
                            "id": vuln_id,
                            "severity": severity,
                            "description": vuln.get("description", ""),
                        }
                    )

    analysis.vulnerable_components = sum(1 for c in analysis.components if c.vulnerabilities)
    if analysis.total_components > 0:
        analysis.supplier_coverage = suppliers_present / analysis.total_components

    return analysis


def parse_spdx(data: dict[str, Any]) -> SBOMAnalysis:
    """Parse an SPDX SBOM JSON document.

    Parameters
    ----------
    data: parsed JSON of an SPDX document
    """
    analysis = SBOMAnalysis(format="spdx")
    analysis.spec_version = data.get("spdxVersion", "")

    packages = data.get("packages", [])
    analysis.total_components = len(packages)

    suppliers_present = 0
    for pkg in packages:
        c = SBOMComponent(
            name=pkg.get("name", "unknown"),
            version=pkg.get("versionInfo", ""),
        )
        supplier = pkg.get("supplier", "")
        if supplier and supplier != "NOASSERTION":
            c.supplier = supplier
            suppliers_present += 1

        lic_concluded = pkg.get("licenseConcluded", "")
        if lic_concluded and lic_concluded != "NOASSERTION":
            c.licenses.append(lic_concluded)

        for checksum in pkg.get("checksums", []):
            if isinstance(checksum, dict):
                c.hashes[checksum.get("algorithm", "")] = checksum.get("checksumValue", "")

        ext_refs = pkg.get("externalRefs", [])
        for ref in ext_refs:
            if ref.get("referenceCategory") == "PACKAGE-MANAGER":
                c.purl = ref.get("referenceLocator", "")

        analysis.components.append(c)

    if analysis.total_components > 0:
        analysis.supplier_coverage = suppliers_present / analysis.total_components

    return analysis


def parse_sbom(content: str) -> SBOMAnalysis:
    """Auto-detect and parse an SBOM document (CycloneDX or SPDX JSON).

    Parameters
    ----------
    content: raw JSON string of the SBOM
    """
    data = json.loads(content)

    if "bomFormat" in data or "specVersion" in data:
        return parse_cyclonedx(data)
    if "spdxVersion" in data:
        return parse_spdx(data)

    # Heuristic: check for CycloneDX-style components
    if "components" in data:
        return parse_cyclonedx(data)
    if "packages" in data:
        return parse_spdx(data)

    log.warning("Unable to detect SBOM format, attempting CycloneDX parse")
    return parse_cyclonedx(data)


# ---------------------------------------------------------------------------
# License risk assessment
# ---------------------------------------------------------------------------

_COPYLEFT_LICENSES = {
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EUPL-1.2",
}


@dataclass
class VEXStatement:
    """A single VEX (Vulnerability Exploitability eXchange) statement."""

    vulnerability_id: str
    status: str = ""  # "not_affected", "affected", "fixed", "under_investigation"
    justification: str = ""  # "component_not_present", "vulnerable_code_not_reachable", etc.
    impact_statement: str = ""
    action_statement: str = ""
    product: str = ""
    subcomponents: list[str] = field(default_factory=list)


@dataclass
class VEXDocument:
    """Parsed VEX document."""

    format: str = ""  # "csaf", "openvex", "cyclonedx"
    doc_id: str = ""
    timestamp: str = ""
    statements: list[VEXStatement] = field(default_factory=list)
    total_statements: int = 0
    not_affected_count: int = 0
    affected_count: int = 0
    fixed_count: int = 0
    under_investigation_count: int = 0


def parse_vex(content: str) -> VEXDocument:
    """Auto-detect and parse a VEX document (OpenVEX, CSAF-VEX, or CycloneDX VEX).

    Parameters
    ----------
    content: raw JSON string of the VEX document
    """
    data = json.loads(content)

    # OpenVEX format
    if data.get("@context") or data.get("@type") == "https://openvex.dev/ns/v0.2.0":
        return _parse_openvex(data)

    # CSAF VEX format
    if "document" in data and "vulnerabilities" in data:
        return _parse_csaf_vex(data)

    # CycloneDX VEX (embedded in BOM with vulnerabilities + analysis)
    if ("bomFormat" in data or "specVersion" in data) and "vulnerabilities" in data:
        return _parse_cyclonedx_vex(data)

    # Fallback: try OpenVEX if it has "statements"
    if "statements" in data:
        return _parse_openvex(data)

    log.warning("Unable to detect VEX format, attempting OpenVEX parse")
    return _parse_openvex(data)


def _parse_openvex(data: dict[str, Any]) -> VEXDocument:
    """Parse an OpenVEX format document."""
    doc = VEXDocument(format="openvex")
    doc.doc_id = data.get("@id", data.get("id", ""))
    doc.timestamp = data.get("timestamp", "")

    for stmt in data.get("statements", []):
        vuln = stmt.get("vulnerability", {})
        vuln_id = vuln.get("name", vuln.get("@id", "")) if isinstance(vuln, dict) else str(vuln)
        status = stmt.get("status", "")
        justification = stmt.get("justification", "")
        impact = stmt.get("impact_statement", "")
        action = stmt.get("action_statement", "")

        products = stmt.get("products", [])
        product_name = ""
        subcomps: list[str] = []
        for prod in products:
            if isinstance(prod, dict):
                product_name = prod.get("@id", prod.get("name", ""))
                for sc in prod.get("subcomponents", []):
                    if isinstance(sc, dict):
                        subcomps.append(sc.get("@id", sc.get("name", "")))
                    else:
                        subcomps.append(str(sc))
            else:
                product_name = str(prod)

        doc.statements.append(
            VEXStatement(
                vulnerability_id=vuln_id,
                status=status,
                justification=justification,
                impact_statement=impact,
                action_statement=action,
                product=product_name,
                subcomponents=subcomps,
            )
        )

    doc.total_statements = len(doc.statements)
    doc.not_affected_count = sum(1 for s in doc.statements if s.status == "not_affected")
    doc.affected_count = sum(1 for s in doc.statements if s.status == "affected")
    doc.fixed_count = sum(1 for s in doc.statements if s.status == "fixed")
    doc.under_investigation_count = sum(
        1 for s in doc.statements if s.status == "under_investigation"
    )
    return doc


def _parse_csaf_vex(data: dict[str, Any]) -> VEXDocument:
    """Parse a CSAF VEX format document."""
    doc = VEXDocument(format="csaf")
    tracking = data.get("document", {}).get("tracking", {})
    doc.doc_id = tracking.get("id", "")
    doc.timestamp = tracking.get("current_release_date", "")

    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", "")
        for flag in vuln.get("flags", []):
            product_ids = flag.get("product_ids", [])
            doc.statements.append(
                VEXStatement(
                    vulnerability_id=cve,
                    status="not_affected",
                    justification=flag.get("label", ""),
                    product=", ".join(product_ids),
                )
            )
        for remediation in vuln.get("remediations", []):
            product_ids = remediation.get("product_ids", [])
            category = remediation.get("category", "")
            status = "fixed" if category == "fix" else "affected"
            doc.statements.append(
                VEXStatement(
                    vulnerability_id=cve,
                    status=status,
                    action_statement=remediation.get("details", ""),
                    product=", ".join(product_ids),
                )
            )
        # Threats as under_investigation
        for threat in vuln.get("threats", []):
            if threat.get("category") == "impact":
                product_ids = threat.get("product_ids", [])
                doc.statements.append(
                    VEXStatement(
                        vulnerability_id=cve,
                        status="under_investigation",
                        impact_statement=threat.get("details", ""),
                        product=", ".join(product_ids),
                    )
                )

    doc.total_statements = len(doc.statements)
    doc.not_affected_count = sum(1 for s in doc.statements if s.status == "not_affected")
    doc.affected_count = sum(1 for s in doc.statements if s.status == "affected")
    doc.fixed_count = sum(1 for s in doc.statements if s.status == "fixed")
    doc.under_investigation_count = sum(
        1 for s in doc.statements if s.status == "under_investigation"
    )
    return doc


def _parse_cyclonedx_vex(data: dict[str, Any]) -> VEXDocument:
    """Parse CycloneDX BOM with VEX vulnerability analysis."""
    doc = VEXDocument(format="cyclonedx")
    doc.spec_version = data.get("specVersion", "")

    for vuln in data.get("vulnerabilities", []):
        vuln_id = vuln.get("id", "")
        analysis = vuln.get("analysis", {})
        state = analysis.get("state", "")
        justification = analysis.get("justification", "")
        detail = analysis.get("detail", "")
        response = analysis.get("response", [])

        # Map CycloneDX analysis states to VEX statuses
        status_map = {
            "resolved": "fixed",
            "resolved_with_pedigree": "fixed",
            "exploitable": "affected",
            "in_triage": "under_investigation",
            "false_positive": "not_affected",
            "not_affected": "not_affected",
        }
        status = status_map.get(state, state)

        affected = vuln.get("affects", [])
        for affect in affected:
            ref = affect.get("ref", "")
            doc.statements.append(
                VEXStatement(
                    vulnerability_id=vuln_id,
                    status=status,
                    justification=justification,
                    impact_statement=detail,
                    action_statement=", ".join(response) if response else "",
                    product=ref,
                )
            )

        if not affected:
            doc.statements.append(
                VEXStatement(
                    vulnerability_id=vuln_id,
                    status=status,
                    justification=justification,
                    impact_statement=detail,
                    action_statement=", ".join(response) if response else "",
                )
            )

    doc.total_statements = len(doc.statements)
    doc.not_affected_count = sum(1 for s in doc.statements if s.status == "not_affected")
    doc.affected_count = sum(1 for s in doc.statements if s.status == "affected")
    doc.fixed_count = sum(1 for s in doc.statements if s.status == "fixed")
    doc.under_investigation_count = sum(
        1 for s in doc.statements if s.status == "under_investigation"
    )
    return doc


def apply_vex_to_sbom(sbom: SBOMAnalysis, vex: VEXDocument) -> dict[str, Any]:
    """Apply VEX statements to an SBOM analysis.

    Reduces the vulnerability count by marking not_affected/fixed
    vulnerabilities per VEX statements.

    Returns a summary of changes.
    """
    suppressed = 0
    for stmt in vex.statements:
        if stmt.status in ("not_affected", "fixed"):
            for comp in sbom.components:
                comp.vulnerabilities = [
                    v for v in comp.vulnerabilities if v.get("id") != stmt.vulnerability_id
                ]
                # Count suppressions
                original_count = len(comp.vulnerabilities)
                if original_count < len(comp.vulnerabilities):
                    suppressed += 1

    # Recount vulnerable components
    new_vuln_count = sum(1 for c in sbom.components if c.vulnerabilities)
    original_vuln_count = sbom.vulnerable_components
    sbom.vulnerable_components = new_vuln_count

    return {
        "vex_statements_applied": vex.total_statements,
        "not_affected": vex.not_affected_count,
        "fixed": vex.fixed_count,
        "original_vulnerable_components": original_vuln_count,
        "remaining_vulnerable_components": new_vuln_count,
        "components_cleared": max(0, original_vuln_count - new_vuln_count),
    }


def assess_license_risk(analysis: SBOMAnalysis) -> list[dict[str, Any]]:
    """Identify license compliance risks in SBOM components.

    Returns a list of risk entries for components with copyleft or unknown licenses.
    """
    risks: list[dict[str, Any]] = []
    for comp in analysis.components:
        if not comp.licenses:
            risks.append(
                {
                    "component": comp.name,
                    "version": comp.version,
                    "risk": "no_license",
                    "severity": "medium",
                    "description": "No license declared",
                }
            )
            continue
        for lic in comp.licenses:
            if lic in _COPYLEFT_LICENSES:
                risks.append(
                    {
                        "component": comp.name,
                        "version": comp.version,
                        "risk": "copyleft",
                        "severity": "high",
                        "license": lic,
                        "description": f"Copyleft license {lic} may require source disclosure",
                    }
                )
    analysis.license_risks = risks
    return risks
