"""ServiceNow GRC normalizer — transforms raw GRC table data into Findings."""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

_RISK_SEVERITY_MAP: dict[str, str] = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class ServiceNowGRCNormalizer(BaseNormalizer):
    """Dispatches ServiceNow GRC event types to type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "servicenow_grc_policies": "_normalize_policies",
        "servicenow_grc_controls": "_normalize_controls",
        "servicenow_grc_risks": "_normalize_risks",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "servicenow_grc" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "servicenow_grc",
            "source_type": SourceType.ITSM,
            "provider": "servicenow_grc",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for item in raw.raw_data.get("response", []):
            sys_id = str(item.get("sys_id", {}).get("value", "") if isinstance(item.get("sys_id"), dict) else item.get("sys_id", ""))
            name = item.get("name", {}).get("value", "") if isinstance(item.get("name"), dict) else str(item.get("name", "unknown"))
            state = item.get("state", {}).get("display_value", "") if isinstance(item.get("state"), dict) else str(item.get("state", ""))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ServiceNow GRC policy: {name}",
                    detail={
                        "sys_id": sys_id,
                        "name": name,
                        "state": state,
                        "category": item.get("category", {}).get("display_value", "") if isinstance(item.get("category"), dict) else str(item.get("category", "")),
                        "description": item.get("description", {}).get("value", "") if isinstance(item.get("description"), dict) else str(item.get("description", "")),
                    },
                    resource_id=sys_id,
                    resource_type="servicenow_grc_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_controls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for item in raw.raw_data.get("response", []):
            sys_id = str(item.get("sys_id", {}).get("value", "") if isinstance(item.get("sys_id"), dict) else item.get("sys_id", ""))
            name = item.get("name", {}).get("value", "") if isinstance(item.get("name"), dict) else str(item.get("name", "unknown"))
            state = item.get("state", {}).get("display_value", "") if isinstance(item.get("state"), dict) else str(item.get("state", ""))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"ServiceNow GRC control: {name}",
                    detail={
                        "sys_id": sys_id,
                        "name": name,
                        "state": state,
                        "control_type": item.get("control_type", {}).get("display_value", "") if isinstance(item.get("control_type"), dict) else str(item.get("control_type", "")),
                        "owner": item.get("owner", {}).get("display_value", "") if isinstance(item.get("owner"), dict) else str(item.get("owner", "")),
                    },
                    resource_id=sys_id,
                    resource_type="servicenow_grc_control",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )
        return findings

    def _normalize_risks(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        for item in raw.raw_data.get("response", []):
            sys_id = str(item.get("sys_id", {}).get("value", "") if isinstance(item.get("sys_id"), dict) else item.get("sys_id", ""))
            name = item.get("name", {}).get("value", "") if isinstance(item.get("name"), dict) else str(item.get("name", "unknown"))
            raw_rating = item.get("risk_rating", {}).get("value", "4") if isinstance(item.get("risk_rating"), dict) else str(item.get("risk_rating", "4"))
            severity = _RISK_SEVERITY_MAP.get(str(raw_rating), "medium")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"ServiceNow GRC risk: {name}",
                    detail={
                        "sys_id": sys_id,
                        "name": name,
                        "risk_rating": raw_rating,
                        "state": item.get("state", {}).get("display_value", "") if isinstance(item.get("state"), dict) else str(item.get("state", "")),
                        "category": item.get("category", {}).get("display_value", "") if isinstance(item.get("category"), dict) else str(item.get("category", "")),
                        "owner": item.get("owner", {}).get("display_value", "") if isinstance(item.get("owner"), dict) else str(item.get("owner", "")),
                    },
                    resource_id=sys_id,
                    resource_type="servicenow_grc_risk",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )
        return findings


registry.register(ServiceNowGRCNormalizer())
