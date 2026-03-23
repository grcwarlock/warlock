"""Microsoft Patch Management normalizer — transforms raw Graph API responses into Findings.

Normalizes compliance policies (as inventory) and managed devices (as
vulnerability findings for non-compliant devices, inventory for compliant ones).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class MicrosoftPatchMgmtNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "microsoft_compliance_policies": "_normalize_compliance_policies",
        "microsoft_managed_devices": "_normalize_managed_devices",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return (
            raw_event.source == "patch_mgmt_microsoft"
            and raw_event.event_type in self.HANDLERS
        )

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "patch_mgmt_microsoft",
            "source_type": SourceType.MDM,
            "provider": "patch_mgmt_microsoft",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Compliance policies --

    def _normalize_compliance_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            display_name = policy.get("displayName", "unknown")
            platform = policy.get("platformType", "unknown")
            version = policy.get("version", "")
            created = policy.get("createdDateTime", "")
            modified = policy.get("lastModifiedDateTime", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Microsoft compliance policy: {display_name}",
                    detail={
                        "policy_id": policy_id,
                        "display_name": display_name,
                        "platform": platform,
                        "version": version,
                        "created_at": created,
                        "modified_at": modified,
                    },
                    resource_id=policy_id,
                    resource_type="microsoft_compliance_policy",
                    resource_name=display_name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    # -- Managed devices --

    def _normalize_managed_devices(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for device in items:
            device_id = str(device.get("id", ""))
            device_name = device.get("deviceName", "unknown")
            os_name = device.get("operatingSystem", "unknown")
            os_version = device.get("osVersion", "")
            compliance_state = device.get("complianceState", "unknown")
            last_sync = device.get("lastSyncDateTime", "")
            owner_type = device.get("managedDeviceOwnerType", "unknown")

            if compliance_state == "compliant":
                obs_type = "inventory"
                severity = "info"
                title = f"Microsoft managed device (compliant): {device_name}"
            else:
                obs_type = "vulnerability"
                severity = "medium" if compliance_state == "noncompliant" else "low"
                title = f"Microsoft managed device non-compliant: {device_name}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "device_id": device_id,
                        "device_name": device_name,
                        "os": os_name,
                        "os_version": os_version,
                        "compliance_state": compliance_state,
                        "last_sync": last_sync,
                        "owner_type": owner_type,
                    },
                    resource_id=device_id,
                    resource_type="microsoft_managed_device",
                    resource_name=device_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(MicrosoftPatchMgmtNormalizer())
