"""Tailscale normalizer — transforms raw Tailscale API responses into Findings.

Normalizes device inventory (as inventory findings) and ACL policies
(as inventory findings documenting access control configuration).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class TailscaleNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Tailscale findings."""

    HANDLERS: dict[str, str] = {
        "tailscale_devices": "_normalize_devices",
        "tailscale_acl": "_normalize_acl",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "tailscale" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "tailscale",
            "source_type": SourceType.NETWORK,
            "provider": "tailscale",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        devices = response if isinstance(response, list) else response.get("devices", [])

        for device in devices:
            device_id = str(device.get("id", device.get("nodeId", "")))
            name = device.get("name", device.get("hostname", "unknown"))
            os_type = device.get("os", "")
            authorized = device.get("authorized", True)

            # Unauthorized devices are a misconfiguration concern
            severity = "medium" if not authorized else "info"
            obs_type = "misconfiguration" if not authorized else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Tailscale device: {name}",
                    detail={
                        "device_id": device_id,
                        "name": name,
                        "os": os_type,
                        "authorized": authorized,
                        "last_seen": device.get("lastSeen", ""),
                        "ip_addresses": device.get("addresses", []),
                        "tags": device.get("tags", []),
                    },
                    resource_id=device_id,
                    resource_type="tailscale_device",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_acl(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})

        # ACL is typically a single policy object
        acl = response if isinstance(response, dict) else {}

        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title="Tailscale ACL policy",
                detail={
                    "acl_rules": acl.get("acls", []),
                    "groups": acl.get("groups", {}),
                    "hosts": acl.get("hosts", {}),
                    "ssh_rules": acl.get("ssh", []),
                    "tag_owners": acl.get("tagOwners", {}),
                },
                resource_id="tailscale-acl",
                resource_type="tailscale_acl_policy",
                resource_name="Tailscale ACL Policy",
                severity="info",
                confidence=1.0,
            )
        )

        return findings


# Register
registry.register(TailscaleNormalizer())
