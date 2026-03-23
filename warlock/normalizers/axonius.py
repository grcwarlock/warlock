"""Axonius normalizer — transforms raw Axonius API responses into Findings.

Normalizes device assets, user assets, and adapters as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AxoniusNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "axonius_devices": "_normalize_devices",
        "axonius_users": "_normalize_users",
        "axonius_adapters": "_normalize_adapters",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "axonius" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Axonius findings."""
        return {
            "raw_event_id": raw.id,
            "source": "axonius",
            "source_type": SourceType.CUSTOM,
            "provider": "axonius",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _extract_items(self, raw: RawEventData) -> list:
        """Extract items list from response, handling nested structures."""
        items = raw.raw_data.get("response", [])
        if isinstance(items, dict):
            items = items.get("data", items.get("assets", items.get("results", [items])))
        return items if isinstance(items, list) else [items]

    # -- Devices --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = self._extract_items(raw)

        for device in items:
            # Axonius wraps fields under adapters_data or specific_data
            specific = device.get("specific_data", device) if isinstance(device, dict) else {}
            device_id = str(device.get("internal_axon_id", device.get("id", "")))
            hostname = specific.get("data", {}).get("hostname", device.get("name", "unknown"))
            os_type = specific.get("data", {}).get("os", {})
            if isinstance(os_type, dict):
                os_type = os_type.get("type", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Axonius device: {hostname}",
                    detail={
                        "device_id": device_id,
                        "hostname": hostname,
                        "os_type": os_type,
                        "adapter_count": len(device.get("adapters", [])) if isinstance(device, dict) else 0,
                        "last_seen": device.get("last_seen", ""),
                    },
                    resource_id=device_id,
                    resource_type="axonius_device",
                    resource_name=str(hostname),
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = self._extract_items(raw)

        for user in items:
            specific = user.get("specific_data", user) if isinstance(user, dict) else {}
            user_id = str(user.get("internal_axon_id", user.get("id", "")))
            username = specific.get("data", {}).get("username", user.get("name", "unknown"))
            email = specific.get("data", {}).get("mail", user.get("email", ""))
            is_admin = specific.get("data", {}).get("is_admin", False)

            severity = "medium" if is_admin else "info"
            obs_type = "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Axonius user: {username}",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "email": email,
                        "is_admin": is_admin,
                        "adapter_count": len(user.get("adapters", [])) if isinstance(user, dict) else 0,
                        "last_seen": user.get("last_seen", ""),
                    },
                    resource_id=user_id,
                    resource_type="axonius_user",
                    resource_name=str(username),
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    # -- Adapters --

    def _normalize_adapters(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = self._extract_items(raw)

        for adapter in items:
            adapter_id = str(adapter.get("unique_plugin_name", adapter.get("id", "")))
            name = adapter.get("name", adapter_id)
            status = adapter.get("status", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Axonius adapter: {name}",
                    detail={
                        "adapter_id": adapter_id,
                        "name": name,
                        "status": status,
                        "node_name": adapter.get("node_name", ""),
                    },
                    resource_id=adapter_id,
                    resource_type="axonius_adapter",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AxoniusNormalizer())
