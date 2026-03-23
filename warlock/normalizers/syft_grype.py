"""Syft/Grype normalizer — transforms local scan JSON output into Findings.

Grype vulnerability reports → vulnerability findings.
Syft SBOM reports → inventory findings (one per artifact/package).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_GRYPE_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
    "unknown": "info",
}


class SyftGrypeNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for syft/grype scan output."""

    HANDLERS: dict[str, str] = {
        "syft_grype_vulnerabilities": "_normalize_vulnerabilities",
        "syft_grype_sbom": "_normalize_sbom",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "syft_grype" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "syft_grype",
            "source_type": SourceType.CONTAINER_SECURITY,
            "provider": "syft_grype",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        """Parse grype JSON report. Supports both list-of-matches and dict with 'matches' key."""
        findings = []
        response = raw.raw_data.get("response", [])
        # Response may be a list of match objects directly, or a dict with a 'matches' key.
        if isinstance(response, list):
            matches = response
        else:
            matches = response.get("matches", [])
        scan_file = raw.raw_data.get("file", "")

        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            vuln_id = vuln.get("id", "")
            raw_severity = vuln.get("severity", "unknown").lower()
            severity = _GRYPE_SEVERITY.get(raw_severity, "medium")
            pkg_name = artifact.get("name", "")
            pkg_version = artifact.get("version", "")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Grype: {vuln_id} in {pkg_name}@{pkg_version}",
                    detail={
                        "vuln_id": vuln_id,
                        "severity": raw_severity,
                        "cvss": vuln.get("cvss", []),
                        "description": vuln.get("description", ""),
                        "fix": vuln.get("fix", {}).get("versions", []),
                        "package_name": pkg_name,
                        "package_version": pkg_version,
                        "package_type": artifact.get("type", ""),
                        "scan_file": scan_file,
                    },
                    resource_id=f"{vuln_id}/{pkg_name}",
                    resource_type="grype_vulnerability",
                    resource_name=vuln_id,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_sbom(self, raw: RawEventData) -> list[FindingData]:
        """Parse syft SBOM JSON. Supports both a direct report dict and a list of report dicts."""
        findings = []
        response = raw.raw_data.get("response", [])
        scan_file = raw.raw_data.get("file", "")

        # Response may be a list of SBOM report objects (one per image/target) or a single dict.
        if isinstance(response, list):
            reports = response
        else:
            reports = [response]

        for report in reports:
            # Syft uses 'artifacts'; CycloneDX SBOMs use 'components'; demo uses 'packages'
            artifacts = report.get("artifacts", report.get("packages", report.get("components", [])))
            source_meta = report.get("source", {})
            image_name = report.get("image", "")
            if not image_name and isinstance(source_meta, dict):
                target = source_meta.get("target", {})
                image_name = target.get("userInput", "") if isinstance(target, dict) else str(target)

            for artifact in artifacts:
                pkg_name = artifact.get("name", "")
                pkg_version = artifact.get("version", "")
                purl = artifact.get("purl", "")
                pkg_type = artifact.get("type", purl.split(":")[1] if ":" in purl else "")
                artifact_id = artifact.get("id", f"{pkg_name}@{pkg_version}")
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Syft SBOM: {pkg_name}@{pkg_version}",
                        detail={
                            "artifact_id": artifact_id,
                            "name": pkg_name,
                            "version": pkg_version,
                            "type": pkg_type,
                            "purl": purl,
                            "licenses": artifact.get("licenses", []),
                            "image": image_name,
                            "scan_file": scan_file,
                        },
                        resource_id=str(artifact_id),
                        resource_type="syft_sbom_artifact",
                        resource_name=f"{pkg_name}@{pkg_version}",
                        severity="info",
                        confidence=1.0,
                    )
                )
        return findings


# Register
registry.register(SyftGrypeNormalizer())
