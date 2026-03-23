"""Varonis normalizer — transforms raw Varonis API responses into Findings.

Normalizes alerts as DLP alert findings, data classification and permissions
as inventory findings.
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
}


class VaronisNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Varonis DLP findings."""

    HANDLERS: dict[str, str] = {
        "varonis_alerts": "_normalize_alerts",
        "varonis_data_classification": "_normalize_data_classification",
        "varonis_permissions": "_normalize_permissions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "varonis" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "varonis",
            "source_type": SourceType.DLP,
            "provider": "varonis",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("alerts", response.get("data", []))
        )

        for alert in items:
            alert_id = str(alert.get("ID", alert.get("id", "")))
            name = alert.get("Name", alert.get("name", "Varonis Alert"))
            severity_raw = str(alert.get("Severity", alert.get("severity", "low"))).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Varonis alert: {name}",
                    detail={
                        "alert_id": alert_id,
                        "name": name,
                        "severity": severity_raw,
                        "category": alert.get("Category", alert.get("category", "")),
                        "user": alert.get("UserName", alert.get("user", "")),
                        "device": alert.get("DeviceName", alert.get("device", "")),
                        "status": alert.get("Status", alert.get("status", "")),
                        "time": alert.get("Time", alert.get("time", "")),
                    },
                    resource_id=alert_id,
                    resource_type="varonis_alert",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_data_classification(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("classifications", response.get("data", []))
        )

        for item in items:
            item_id = str(item.get("id", item.get("objectId", "")))
            name = item.get("name", item.get("objectName", "unknown"))
            classification = item.get("classification", item.get("type", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Varonis data classification: {name}",
                    detail={
                        "object_id": item_id,
                        "name": name,
                        "classification": classification,
                        "path": item.get("path", ""),
                        "owner": item.get("owner", ""),
                        "sensitivity": item.get("sensitivity", ""),
                    },
                    resource_id=item_id,
                    resource_type="varonis_data_object",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_permissions(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("permissions", response.get("data", []))
        )

        for perm in items:
            perm_id = str(perm.get("id", ""))
            resource_name = perm.get("resource", perm.get("objectName", "unknown"))
            principal = perm.get("principal", perm.get("user", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Varonis permission: {principal} on {resource_name}",
                    detail={
                        "permission_id": perm_id,
                        "resource": resource_name,
                        "principal": principal,
                        "permission_type": perm.get("type", perm.get("permission", "")),
                        "inherited": perm.get("inherited", False),
                    },
                    resource_id=perm_id,
                    resource_type="varonis_permission",
                    resource_name=resource_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(VaronisNormalizer())
