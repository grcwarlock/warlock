"""Snyk Container normalizer — transforms raw Snyk API responses into Findings.

Normalizes container images as inventory, container issues as vulnerability findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SNYK_SEVERITY: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


class SnykContainerNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Snyk container telemetry."""

    HANDLERS: dict[str, str] = {
        "snyk_container_images": "_normalize_images",
        "snyk_container_issues": "_normalize_issues",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "snyk_container" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        return getattr(self, handler_name)(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "snyk_container",
            "source_type": SourceType.CONTAINER_SECURITY,
            "provider": "snyk_container",
            "account_id": raw.raw_data.get("org_id", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_images(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for image in raw.raw_data.get("response", []):
            image_id = str(image.get("id", image.get("imageId", "")))
            name = image.get("name", image.get("imageName", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Snyk container image: {name}",
                    detail={
                        "image_id": image_id,
                        "name": name,
                        "tag": image.get("tag", ""),
                        "digest": image.get("digest", ""),
                        "created": image.get("created", ""),
                        "base_image": image.get("baseImage", ""),
                    },
                    resource_id=image_id,
                    resource_type="snyk_container_image",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_issues(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for issue in raw.raw_data.get("response", []):
            issue_id = str(issue.get("id", ""))
            issue_data = issue.get("issueData", issue)
            title = issue_data.get("title", issue.get("title", issue_id))
            raw_severity = issue_data.get("severity", issue.get("severity", "medium")).lower()
            severity = _SNYK_SEVERITY.get(raw_severity, "medium")
            cve_ids = (
                issue_data.get("identifiers", {}).get("CVE", [])
                if isinstance(issue_data.get("identifiers"), dict)
                else []
            )
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Snyk container issue: {title}",
                    detail={
                        "issue_id": issue_id,
                        "title": title,
                        "severity": raw_severity,
                        "cve": cve_ids,
                        "cvss_score": issue_data.get("cvssScore", ""),
                        "package_name": issue.get("pkgName", ""),
                        "package_version": issue.get("pkgVersions", [""])[0]
                        if issue.get("pkgVersions")
                        else "",
                        "fixed_in": issue_data.get("fixedIn", []),
                        "exploit_maturity": issue_data.get("exploitMaturity", ""),
                    },
                    resource_id=issue_id,
                    resource_type="snyk_container_issue",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings


# Register
registry.register(SnykContainerNormalizer())
