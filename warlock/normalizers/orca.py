"""Orca Security normalizer — transforms CSPM alerts, assets, and compliance into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_ORCA_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


class OrcaNormalizer(BaseNormalizer):
    """Dispatches Orca Security event types to type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "orca_alerts": "_normalize_alerts",
        "orca_assets": "_normalize_assets",
        "orca_compliance": "_normalize_compliance",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "orca" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "orca",
            "source_type": SourceType.CSPM,
            "provider": "orca",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for alert in raw.raw_data.get("response", []):
            alert_id = str(alert.get("alert_id", alert.get("id", "")))
            raw_severity = str(alert.get("severity", "low")).lower()
            severity = _ORCA_SEVERITY_MAP.get(raw_severity, "medium")
            title = alert.get("title", alert.get("type_string", "Orca alert"))
            asset = alert.get("asset_unique_id", "")
            account_id = alert.get("cloud_account_id", "")
            region = alert.get("cloud_region", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Orca alert: {title}",
                    detail={
                        "alert_id": alert_id,
                        "title": title,
                        "severity": raw_severity,
                        "state": alert.get("state", ""),
                        "category": alert.get("category", ""),
                        "asset_unique_id": asset,
                        "account_id": account_id,
                        "region": region,
                        "recommendation": alert.get("recommendation", ""),
                    },
                    resource_id=asset or alert_id,
                    resource_type="orca_alert",
                    resource_name=title,
                    account_id=account_id,
                    region=region,
                    severity=severity,
                    confidence=0.95,
                )
            )
        return findings

    def _normalize_assets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for asset in raw.raw_data.get("response", []):
            asset_id = str(asset.get("asset_unique_id", asset.get("id", "")))
            asset_name = asset.get("asset_name", asset.get("name", "unknown"))
            asset_type = asset.get("asset_type", "")
            account_id = asset.get("cloud_account_id", "")
            region = asset.get("cloud_region", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Orca asset: {asset_name}",
                    detail={
                        "asset_id": asset_id,
                        "asset_name": asset_name,
                        "asset_type": asset_type,
                        "cloud_provider": asset.get("cloud_provider", ""),
                        "account_id": account_id,
                        "region": region,
                        "tags": asset.get("tags", []),
                    },
                    resource_id=asset_id,
                    resource_type=f"orca_{asset_type}" if asset_type else "orca_asset",
                    resource_name=asset_name,
                    account_id=account_id,
                    region=region,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_compliance(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for check in raw.raw_data.get("response", []):
            check_id = str(check.get("rule_id", check.get("id", "")))
            title = check.get("title", check.get("rule_name", "Orca compliance check"))
            status = str(check.get("status", "unknown")).lower()
            raw_severity = str(check.get("severity", "low")).lower()
            severity = _ORCA_SEVERITY_MAP.get(raw_severity, "medium")
            framework = check.get("framework", "")

            obs_type = "policy_violation" if status in ("failed", "fail") else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Orca compliance: {title}",
                    detail={
                        "check_id": check_id,
                        "title": title,
                        "status": status,
                        "framework": framework,
                        "severity": raw_severity,
                        "remediation": check.get("remediation", ""),
                        "affected_resources": check.get("affected_resources_count", 0),
                    },
                    resource_id=check_id,
                    resource_type="orca_compliance_check",
                    resource_name=title,
                    severity=severity,
                    confidence=0.9,
                )
            )
        return findings


registry.register(OrcaNormalizer())
