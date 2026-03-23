"""Vulcan Cyber normalizer — transforms raw Vulcan API responses into Findings.

Normalizes vulnerabilities as vulnerability findings, assets and campaigns
as inventory findings. Severity is mapped from Vulcan's risk score or label.
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
    "none": "info",
}


class VulcanNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Vulcan Cyber findings."""

    HANDLERS: dict[str, str] = {
        "vulcan_assets": "_normalize_assets",
        "vulcan_vulnerabilities": "_normalize_vulnerabilities",
        "vulcan_campaigns": "_normalize_campaigns",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "vulcan" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "vulcan",
            "source_type": SourceType.SCANNER,
            "provider": "vulcan",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("assets", response.get("data", []))

        for asset in items:
            asset_id = str(asset.get("id", ""))
            name = asset.get("name", asset.get("identifier", "unknown"))
            asset_type = asset.get("type", asset.get("assetType", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Vulcan asset: {name}",
                    detail={
                        "asset_id": asset_id,
                        "name": name,
                        "type": asset_type,
                        "tags": asset.get("tags", []),
                        "risk_score": asset.get("riskScore", 0),
                        "owner": asset.get("owner", ""),
                        "last_seen": asset.get("lastSeen", ""),
                    },
                    resource_id=asset_id,
                    resource_type="vulcan_asset",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("vulnerabilities", response.get("data", []))
        )

        for vuln in items:
            vuln_id = str(vuln.get("id", ""))
            title = vuln.get("summary", vuln.get("title", vuln.get("name", "Vulnerability")))
            severity_raw = str(vuln.get("severity", vuln.get("risk", "low"))).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Vulcan vulnerability: {title}",
                    detail={
                        "vuln_id": vuln_id,
                        "title": title,
                        "severity": severity_raw,
                        "cve": vuln.get("cveList", vuln.get("cve", [])),
                        "cvss_score": vuln.get("cvssScore", 0),
                        "asset_id": str(vuln.get("assetId", "")),
                        "fix_available": vuln.get("fixAvailable", False),
                        "status": vuln.get("status", ""),
                    },
                    resource_id=vuln_id,
                    resource_type="vulcan_vulnerability",
                    resource_name=title,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_campaigns(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("campaigns", response.get("data", []))

        for campaign in items:
            campaign_id = str(campaign.get("id", ""))
            name = campaign.get("name", campaign.get("title", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Vulcan campaign: {name}",
                    detail={
                        "campaign_id": campaign_id,
                        "name": name,
                        "status": campaign.get("status", ""),
                        "description": campaign.get("description", ""),
                        "owner": campaign.get("owner", ""),
                        "due_date": campaign.get("dueDate", ""),
                        "vulnerability_count": campaign.get("vulnerabilityCount", 0),
                    },
                    resource_id=campaign_id,
                    resource_type="vulcan_campaign",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(VulcanNormalizer())
