"""Tanium normalizer — transforms raw Tanium API responses into Findings.

Normalizes endpoints as inventory, alerts as alert findings,
missing patches as vulnerability findings.
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


class TaniumNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Tanium EDR findings."""

    HANDLERS: dict[str, str] = {
        "tanium_endpoints": "_normalize_endpoints",
        "tanium_patches": "_normalize_patches",
        "tanium_alerts": "_normalize_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "tanium" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "tanium",
            "source_type": SourceType.EDR,
            "provider": "tanium",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_endpoints(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("endpoints", []))
        )

        for endpoint in items:
            endpoint_id = str(endpoint.get("id", endpoint.get("eid", "")))
            name = endpoint.get("computerName", endpoint.get("name", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Tanium endpoint: {name}",
                    detail={
                        "endpoint_id": endpoint_id,
                        "name": name,
                        "os": (endpoint.get("os") or {}).get("name", "")
                        if isinstance(endpoint.get("os"), dict)
                        else endpoint.get("os", endpoint.get("operatingSystem", "")),
                        "ip_addresses": endpoint.get("ipAddresses", []),
                        "is_encrypted": endpoint.get("isEncrypted", False),
                        "compliance_state": endpoint.get("complianceState", ""),
                        "last_seen": endpoint.get("lastSeen", ""),
                    },
                    resource_id=endpoint_id,
                    resource_type="tanium_endpoint",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_patches(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("patches", []))
        )

        for patch in items:
            patch_id = str(patch.get("id", patch.get("bulletinId", "")))
            name = patch.get("name", patch.get("title", "Patch"))
            severity_raw = str(patch.get("severity", "low")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")
            is_installed = patch.get("installed", patch.get("isInstalled", True))

            # Uninstalled patches are vulnerability findings
            obs_type = "vulnerability" if not is_installed else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Tanium patch {'missing' if not is_installed else 'installed'}: {name}",
                    detail={
                        "patch_id": patch_id,
                        "name": name,
                        "severity": severity_raw,
                        "is_installed": is_installed,
                        "kb_article": patch.get("kbArticleId", ""),
                        "cve": patch.get("cveList", []),
                        "release_date": patch.get("releaseDate", ""),
                    },
                    resource_id=patch_id,
                    resource_type="tanium_patch",
                    resource_name=name,
                    severity=severity if not is_installed else "info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("alerts", []))
        )

        for alert in items:
            alert_id = str(alert.get("id", alert.get("alertId", "")))
            name = alert.get("name", alert.get("type", "Tanium Alert"))
            severity_raw = str(alert.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(severity_raw, "medium")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Tanium alert: {name}",
                    detail={
                        "alert_id": alert_id,
                        "name": name,
                        "severity": severity_raw,
                        "state": alert.get("state", ""),
                        "endpoint_name": alert.get("computerName", ""),
                        "process": alert.get("processName", ""),
                        "detected_at": alert.get("createdAt", ""),
                        "intel_doc_id": str(alert.get("intelDocId", "")),
                    },
                    resource_id=alert_id,
                    resource_type="tanium_alert",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(TaniumNormalizer())
