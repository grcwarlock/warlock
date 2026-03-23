"""Banyan Security normalizer — transforms raw Banyan API responses into Findings.

Normalizes services, policies, and devices as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class BanyanNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Banyan Security findings."""

    HANDLERS: dict[str, str] = {
        "banyan_services": "_normalize_services",
        "banyan_policies": "_normalize_policies",
        "banyan_devices": "_normalize_devices",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "banyan" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "banyan",
            "source_type": SourceType.NETWORK,
            "provider": "banyan",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_services(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("services", []))
        )

        for service in items:
            service_id = str(service.get("ServiceID", service.get("id", "")))
            name = service.get("ServiceName", service.get("name", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Banyan service: {name}",
                    detail={
                        "service_id": service_id,
                        "name": name,
                        "description": service.get("Description", ""),
                        "type": service.get("Type", ""),
                        "cluster": service.get("ClusterName", ""),
                        "enabled": service.get("Enabled", True),
                    },
                    resource_id=service_id,
                    resource_type="banyan_service",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("policies", []))
        )

        for policy in items:
            policy_id = str(policy.get("PolicyID", policy.get("id", "")))
            name = policy.get("PolicyName", policy.get("name", "unknown"))
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Banyan policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "description": policy.get("Description", ""),
                        "type": policy.get("Type", ""),
                        "enabled": policy.get("Enabled", True),
                    },
                    resource_id=policy_id,
                    resource_type="banyan_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = (
            response
            if isinstance(response, list)
            else response.get("data", response.get("devices", []))
        )

        for device in items:
            device_id = str(device.get("SerialNumber", device.get("id", "")))
            name = device.get("DeviceFriendlyName", device.get("name", "unknown"))
            registered = device.get("IsRegistered", True)
            severity = "medium" if not registered else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Banyan device: {name}",
                    detail={
                        "device_id": device_id,
                        "name": name,
                        "os": device.get("Platform", ""),
                        "os_version": device.get("OSVersion", ""),
                        "registered": registered,
                        "last_login": device.get("LastLoginAt", ""),
                    },
                    resource_id=device_id,
                    resource_type="banyan_device",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(BanyanNormalizer())
