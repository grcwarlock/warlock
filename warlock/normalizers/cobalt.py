"""Cobalt normalizer — transforms raw Cobalt PtaaS API responses into Findings.

Normalizes pentest findings as vulnerability findings with severity from the provider,
assets and pentests as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "null": "info",
}


class CobaltNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Cobalt PtaaS findings."""

    HANDLERS: dict[str, str] = {
        "cobalt_assets": "_normalize_assets",
        "cobalt_pentests": "_normalize_pentests",
        "cobalt_findings": "_normalize_findings",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cobalt" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "cobalt",
            "source_type": SourceType.CUSTOM,
            "provider": "cobalt",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for asset in items:
            resource = asset.get("resource", asset)
            asset_id = str(resource.get("id", ""))
            name = resource.get("title", resource.get("name", "unknown"))
            asset_type = resource.get("asset_type", resource.get("type", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cobalt asset: {name}",
                    detail={
                        "asset_id": asset_id,
                        "name": name,
                        "type": asset_type,
                        "description": resource.get("description", ""),
                        "tags": resource.get("tags", []),
                        "attachments": resource.get("attachments", []),
                    },
                    resource_id=asset_id,
                    resource_type="cobalt_asset",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_pentests(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for pentest in items:
            resource = pentest.get("resource", pentest)
            pentest_id = str(resource.get("id", ""))
            name = resource.get("title", resource.get("name", "unknown"))
            state = resource.get("state", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cobalt pentest: {name}",
                    detail={
                        "pentest_id": pentest_id,
                        "name": name,
                        "state": state,
                        "objectives": resource.get("objectives", ""),
                        "asset_id": str(resource.get("asset", {}).get("id", "")),
                        "start_date": resource.get("start_date", ""),
                        "end_date": resource.get("end_date", ""),
                        "methodology": resource.get("methodology", ""),
                    },
                    resource_id=pentest_id,
                    resource_type="cobalt_pentest",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_findings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for finding in items:
            resource = finding.get("resource", finding)
            finding_id = str(resource.get("id", ""))
            title = resource.get("title", resource.get("name", "Cobalt Finding"))
            severity_raw = str(resource.get("severity", "low")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")
            state = resource.get("state", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Cobalt finding: {title}",
                    detail={
                        "finding_id": finding_id,
                        "title": title,
                        "severity": severity_raw,
                        "state": state,
                        "type_category": resource.get("type_category", ""),
                        "pentest_id": str(resource.get("pentest", {}).get("id", "")),
                        "asset_id": str(resource.get("asset", {}).get("id", "")),
                        "description": resource.get("description", ""),
                        "impact": resource.get("impact", ""),
                        "remediation": resource.get("suggested_fix", ""),
                        "cvss_score": resource.get("cvss_score", 0),
                        "cvss_vector": resource.get("cvss_vector", ""),
                        "cve": resource.get("cve_ids", []),
                    },
                    resource_id=finding_id,
                    resource_type="cobalt_finding",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CobaltNormalizer())
