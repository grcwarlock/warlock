"""Cisco Umbrella normalizer — transforms raw Umbrella API responses into Findings.

Normalizes roaming computers, policies, and destination lists as inventory findings.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CiscoUmbrellaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "umbrella_roaming_computers": "_normalize_roaming_computers",
        "umbrella_policies": "_normalize_policies",
        "umbrella_destination_lists": "_normalize_destination_lists",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cisco_umbrella" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "cisco_umbrella",
            "source_type": SourceType.NETWORK,
            "provider": "cisco_umbrella",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_roaming_computers(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for computer in items:
            computer_id = str(computer.get("deviceId", computer.get("id", "")))
            name = computer.get("name", "unknown")
            client_version = computer.get("version", "")
            last_sync = computer.get("lastSyncStatus", "synced")
            # Computers not syncing are a compliance gap
            is_synced = str(last_sync).lower() in ("synced", "active", "ok")
            obs_type = "misconfiguration" if not is_synced else "inventory"
            severity = "medium" if not is_synced else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Cisco Umbrella roaming computer: {name}",
                    detail={
                        "device_id": computer_id,
                        "name": name,
                        "client_version": client_version,
                        "last_sync_status": last_sync,
                        "os_version": computer.get("osVersion", ""),
                        "origin_id": str(computer.get("originId", "")),
                        "tags": computer.get("tags", []),
                    },
                    resource_id=computer_id,
                    resource_type="umbrella_roaming_computer",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            is_default = policy.get("isDefault", False)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cisco Umbrella policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "is_default": is_default,
                        "priority": policy.get("priority", 0),
                        "settings": str(policy.get("settings", {})),
                    },
                    resource_id=policy_id,
                    resource_type="umbrella_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_destination_lists(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for dest_list in items:
            list_id = str(dest_list.get("id", ""))
            name = dest_list.get("name", "unknown")
            access = dest_list.get("access", "allow")
            destination_count = dest_list.get("destinationCount", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Cisco Umbrella destination list: {name}",
                    detail={
                        "list_id": list_id,
                        "name": name,
                        "access": access,
                        "destination_count": destination_count,
                        "is_global": dest_list.get("isGlobal", False),
                        "organization_id": str(dest_list.get("organizationId", "")),
                    },
                    resource_id=list_id,
                    resource_type="umbrella_destination_list",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(CiscoUmbrellaNormalizer())
