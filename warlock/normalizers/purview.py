"""Purview normalizer — transforms raw MS Purview API responses into Findings.

Handles DLP alerts, sensitivity labels, and DLP policy inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Graph Security severity string -> standard
PURVIEW_SEVERITY_MAP: dict[str, str] = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


class PurviewNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Purview DLP data."""

    HANDLERS: dict[str, str] = {
        "purview_dlp_alerts": "_normalize_dlp_alerts",
        "purview_sensitivity_labels": "_normalize_sensitivity_labels",
        "purview_dlp_policies": "_normalize_dlp_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "purview" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Purview findings."""
        return {
            "raw_event_id": raw.id,
            "source": "purview",
            "source_type": SourceType.DLP,
            "provider": "purview",
            "observed_at": raw.observed_at,
        }

    # -- DLP Alerts --

    def _normalize_dlp_alerts(self, raw: RawEventData) -> list[FindingData]:
        """One finding per DLP alert."""
        findings = []
        alerts = raw.raw_data.get("records", [])

        for alert in alerts:
            alert_id = alert.get("id", "")
            title = alert.get("title", "Unknown DLP alert")
            severity_str = alert.get("severity", "unknown").lower()
            severity = PURVIEW_SEVERITY_MAP.get(severity_str, "info")
            status = alert.get("status", "")
            category = alert.get("category", "")
            description = alert.get("description", "")
            created = alert.get("createdDateTime", "")
            service_source = alert.get("serviceSource", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"Purview DLP alert: {title}",
                detail={
                    "alert_id": alert_id,
                    "title": title,
                    "severity": severity_str,
                    "status": status,
                    "category": category,
                    "description": description,
                    "created_date_time": created,
                    "service_source": service_source,
                },
                resource_id=alert_id,
                resource_type="dlp_alert",
                resource_name=title,
                severity=severity,
            ))

        return findings

    # -- Sensitivity Labels --

    def _normalize_sensitivity_labels(self, raw: RawEventData) -> list[FindingData]:
        """Label inventory — one finding per sensitivity label."""
        findings = []
        labels = raw.raw_data.get("records", [])

        for label in labels:
            label_id = label.get("id", "")
            name = label.get("name", label.get("displayName", "unknown"))
            description = label.get("description", "")
            is_active = label.get("isActive", True)
            tooltip = label.get("tooltip", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Sensitivity label: {name}",
                detail={
                    "label_id": label_id,
                    "name": name,
                    "description": description,
                    "is_active": is_active,
                    "tooltip": tooltip,
                },
                resource_id=label_id,
                resource_type="dlp_label",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- DLP Policies --

    def _normalize_dlp_policies(self, raw: RawEventData) -> list[FindingData]:
        """Policy inventory — disabled policies become misconfigurations."""
        findings = []
        policies = raw.raw_data.get("records", [])

        for policy in policies:
            policy_id = policy.get("id", "")
            name = policy.get("name", policy.get("displayName", "unknown"))
            description = policy.get("description", "")
            is_enabled = policy.get("isEnabled", True)

            if not is_enabled:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"DLP policy disabled: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "description": description,
                        "is_enabled": False,
                        "issue": "dlp_policy_disabled",
                    },
                    resource_id=policy_id,
                    resource_type="dlp_policy",
                    resource_name=name,
                    severity="medium",
                ))
            else:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"DLP policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "description": description,
                        "is_enabled": True,
                    },
                    resource_id=policy_id,
                    resource_type="dlp_policy",
                    resource_name=name,
                    severity="info",
                ))

        return findings


# Register
registry.register(PurviewNormalizer())
