"""Chainguard normalizer — transforms raw Chainguard API responses into Findings.

Normalizes images as inventory, policies as inventory,
and vulnerabilities as vulnerability findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_CVSS_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
    "unknown": "info",
}


class ChainguardNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Chainguard telemetry."""

    HANDLERS: dict[str, str] = {
        "chainguard_images": "_normalize_images",
        "chainguard_policies": "_normalize_policies",
        "chainguard_vulnerabilities": "_normalize_vulnerabilities",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "chainguard" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "chainguard",
            "source_type": SourceType.CONTAINER_SECURITY,
            "provider": "chainguard",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_images(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for image in raw.raw_data.get("response", []):
            image_id = str(image.get("id", image.get("digest", "")))
            name = image.get("name", image.get("repository", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Chainguard image: {name}",
                    detail={
                        "image_id": image_id,
                        "name": name,
                        "digest": image.get("digest", ""),
                        "tag": image.get("tag", ""),
                        "created_at": image.get("createdAt", ""),
                        "signed": image.get("signed", False),
                    },
                    resource_id=image_id,
                    resource_type="chainguard_image",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for policy in raw.raw_data.get("response", []):
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Chainguard policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "description": policy.get("description", ""),
                        "enforcement": policy.get("enforcement", ""),
                        "created_at": policy.get("createdAt", ""),
                    },
                    resource_id=policy_id,
                    resource_type="chainguard_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for vuln in raw.raw_data.get("response", []):
            vuln_id = str(vuln.get("id", vuln.get("cveId", "")))
            title = vuln.get("title", vuln_id)
            raw_severity = vuln.get("severity", "unknown").lower()
            severity = _CVSS_SEVERITY.get(raw_severity, "medium")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Chainguard vulnerability: {vuln_id}",
                    detail={
                        "vuln_id": vuln_id,
                        "title": title,
                        "severity": raw_severity,
                        "cvss_score": vuln.get("cvssScore", ""),
                        "affected_package": vuln.get("affectedPackage", ""),
                        "fixed_version": vuln.get("fixedVersion", ""),
                        "image": vuln.get("image", ""),
                    },
                    resource_id=vuln_id,
                    resource_type="chainguard_vulnerability",
                    resource_name=vuln_id,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(ChainguardNormalizer())
