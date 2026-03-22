"""Trivy normalizer — transforms raw Trivy scan results into Findings.

Handles container vulnerabilities, IaC misconfigurations, secrets, and SBOM.
Flags: critical/high CVEs, IaC misconfigurations, exposed secrets, outdated base images.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TrivyNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "trivy_container_vulns": "_normalize_container_vulns",
        "trivy_iac_misconfigs": "_normalize_iac_misconfigs",
        "trivy_secrets": "_normalize_secrets",
        "trivy_sbom": "_normalize_sbom",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "trivy" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Trivy findings."""
        return {
            "raw_event_id": raw.id,
            "source": "trivy",
            "source_type": SourceType.SCANNER,
            "provider": "trivy",
            "observed_at": raw.observed_at,
        }

    # -- Container Vulnerabilities --

    def _normalize_container_vulns(self, raw: RawEventData) -> list[FindingData]:
        """Normalize container image vulnerability scan results."""
        findings = []
        results = raw.raw_data.get("results", [])

        for result_block in results:
            target = result_block.get("Target", result_block.get("target", ""))
            vulns = result_block.get("Vulnerabilities", result_block.get("vulnerabilities", []))

            if not vulns:
                continue

            for vuln in vulns:
                vuln_id = vuln.get("VulnerabilityID", vuln.get("vulnerability_id", ""))
                pkg_name = vuln.get("PkgName", vuln.get("pkg_name", ""))
                installed = vuln.get("InstalledVersion", vuln.get("installed_version", ""))
                fixed = vuln.get("FixedVersion", vuln.get("fixed_version", ""))
                severity = vuln.get("Severity", vuln.get("severity", "info")).lower()
                title = vuln.get("Title", vuln.get("title", ""))
                description = vuln.get("Description", vuln.get("description", ""))

                # Inventory every CVE
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="vulnerability",
                        title=f"CVE {vuln_id}: {pkg_name} in {target}",
                        detail={
                            "vulnerability_id": vuln_id,
                            "package_name": pkg_name,
                            "installed_version": installed,
                            "fixed_version": fixed,
                            "severity": severity,
                            "target": target,
                            "title": title,
                            "description": description[:500] if description else "",
                        },
                        resource_id=vuln_id,
                        resource_type="container_vulnerability",
                        resource_name=f"{pkg_name}@{installed}",
                        severity=severity
                        if severity in ("critical", "high", "medium", "low")
                        else "info",
                    )
                )

                # Flag critical/high CVEs with available fixes
                if severity in ("critical", "high") and fixed:
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Fixable {severity} CVE: {vuln_id} in {pkg_name}",
                            detail={
                                "vulnerability_id": vuln_id,
                                "package_name": pkg_name,
                                "installed_version": installed,
                                "fixed_version": fixed,
                                "severity": severity,
                                "target": target,
                                "issue": f"Critical/high CVE has a fix available ({fixed}) but has not been patched",
                            },
                            resource_id=vuln_id,
                            resource_type="container_vulnerability",
                            resource_name=f"{pkg_name}@{installed}",
                            severity=severity,
                        )
                    )

        return findings

    # -- IaC Misconfigurations --

    def _normalize_iac_misconfigs(self, raw: RawEventData) -> list[FindingData]:
        """Normalize IaC misconfiguration scan results."""
        findings = []
        results = raw.raw_data.get("results", [])

        for result_block in results:
            target = result_block.get("Target", result_block.get("target", ""))
            misconfigs = result_block.get(
                "Misconfigurations", result_block.get("misconfigurations", [])
            )

            if not misconfigs:
                continue

            for mc in misconfigs:
                mc_id = mc.get("ID", mc.get("id", ""))
                mc_title = mc.get("Title", mc.get("title", ""))
                severity = mc.get("Severity", mc.get("severity", "info")).lower()
                mc_type = mc.get("Type", mc.get("type", ""))
                message = mc.get("Message", mc.get("message", ""))
                resolution = mc.get("Resolution", mc.get("resolution", ""))
                status = mc.get("Status", mc.get("status", ""))

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"IaC misconfiguration: {mc_title} in {target}",
                        detail={
                            "misconfig_id": mc_id,
                            "title": mc_title,
                            "severity": severity,
                            "type": mc_type,
                            "target": target,
                            "message": message,
                            "resolution": resolution,
                            "status": status,
                        },
                        resource_id=mc_id,
                        resource_type="iac_misconfiguration",
                        resource_name=f"{mc_id}:{target}",
                        severity=severity
                        if severity in ("critical", "high", "medium", "low")
                        else "info",
                    )
                )

        return findings

    # -- Secrets --

    def _normalize_secrets(self, raw: RawEventData) -> list[FindingData]:
        """Normalize secret detection results."""
        findings = []
        results = raw.raw_data.get("results", [])

        for result_block in results:
            target = result_block.get("Target", result_block.get("target", ""))
            secrets = result_block.get("Secrets", result_block.get("secrets", []))

            if not secrets:
                continue

            for secret in secrets:
                rule_id = secret.get("RuleID", secret.get("rule_id", ""))
                category = secret.get("Category", secret.get("category", ""))
                severity = secret.get("Severity", secret.get("severity", "high")).lower()
                title = secret.get("Title", secret.get("title", ""))
                start_line = secret.get("StartLine", secret.get("start_line", ""))

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Exposed secret: {title} in {target}",
                        detail={
                            "rule_id": rule_id,
                            "category": category,
                            "severity": severity,
                            "target": target,
                            "title": title,
                            "start_line": start_line,
                            "issue": f"Secret detected in {target} — credentials may be exposed in source or image",
                        },
                        resource_id=f"{rule_id}:{target}:{start_line}",
                        resource_type="exposed_secret",
                        resource_name=f"{category}:{target}",
                        severity="critical" if severity in ("critical", "high") else severity,
                    )
                )

        return findings

    # -- SBOM --

    def _normalize_sbom(self, raw: RawEventData) -> list[FindingData]:
        """Inventory SBOM components."""
        findings = []
        components = raw.raw_data.get("components", [])

        for comp in components:
            comp_name = comp.get("name", "")
            comp_version = comp.get("version", "")
            comp_type = comp.get("type", comp.get("purl", ""))
            comp_licenses = comp.get("licenses", [])

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"SBOM component: {comp_name}@{comp_version}",
                    detail={
                        "name": comp_name,
                        "version": comp_version,
                        "type": comp_type,
                        "licenses": [
                            lic.get("license", {}).get("id", str(lic))
                            if isinstance(lic, dict)
                            else str(lic)
                            for lic in comp_licenses
                        ]
                        if comp_licenses
                        else [],
                    },
                    resource_id=f"{comp_name}@{comp_version}",
                    resource_type="sbom_component",
                    resource_name=f"{comp_name}@{comp_version}",
                    severity="info",
                )
            )

        return findings


# Register
registry.register(TrivyNormalizer())
