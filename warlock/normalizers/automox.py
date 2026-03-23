"""Automox normalizer — transforms raw Automox API responses into Findings.

Normalizes servers as inventory, non-compliant servers as misconfiguration,
policies as inventory, patches as inventory/vulnerability.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AutomoxNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Automox MDM findings."""

    HANDLERS: dict[str, str] = {
        "automox_servers": "_normalize_servers",
        "automox_policies": "_normalize_policies",
        "automox_patches": "_normalize_patches",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "automox" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "automox",
            "source_type": SourceType.MDM,
            "provider": "automox",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_servers(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for server in items:
            server_id = str(server.get("id", ""))
            name = server.get("name", server.get("server_name", "unknown"))
            compliant = server.get("compliant", True)
            os_name = server.get("os_name", server.get("os", ""))

            severity = "high" if not compliant else "info"
            obs_type = "misconfiguration" if not compliant else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Automox server: {name}",
                    detail={
                        "server_id": server_id,
                        "name": name,
                        "os": os_name,
                        "os_version": server.get("os_version", ""),
                        "compliant": compliant,
                        "pending_patch_count": server.get("pending_patch_count", 0),
                        "agent_version": server.get("agent_version", ""),
                        "last_updated": server.get("last_update_time", ""),
                    },
                    resource_id=server_id,
                    resource_type="automox_server",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", policy.get("policy_name", "unknown"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Automox policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "policy_type": policy.get("policy_type_name", policy.get("type", "")),
                        "enabled": policy.get("enabled", True),
                        "server_count": policy.get("server_count", 0),
                        "schedule": policy.get("schedule", ""),
                    },
                    resource_id=policy_id,
                    resource_type="automox_policy",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_patches(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        items = response if isinstance(response, list) else response.get("data", [])

        for patch in items:
            patch_id = str(patch.get("id", ""))
            name = patch.get("display_name", patch.get("name", "Patch"))
            severity_raw = str(patch.get("severity", "")).lower()
            severity_map = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}
            severity = severity_map.get(severity_raw, "info")
            installed = patch.get("installed", True)

            obs_type = "vulnerability" if not installed else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Automox patch {'missing' if not installed else 'installed'}: {name}",
                    detail={
                        "patch_id": patch_id,
                        "name": name,
                        "severity": severity_raw,
                        "installed": installed,
                        "package_name": patch.get("package_name", ""),
                        "vendor": patch.get("vendor", ""),
                        "cves": patch.get("cves", []),
                    },
                    resource_id=patch_id,
                    resource_type="automox_patch",
                    resource_name=name,
                    severity=severity if not installed else "info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(AutomoxNormalizer())
