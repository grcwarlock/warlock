"""Intune normalizer — transforms raw MS Intune API responses into Findings.

Handles device inventory (with compliance, encryption, and OS checks),
compliance policies, and per-device compliance states.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class IntuneNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers for Intune MDM data."""

    HANDLERS: dict[str, str] = {
        "intune_devices": "_normalize_devices",
        "intune_compliance_policies": "_normalize_compliance_policies",
        "intune_compliance_states": "_normalize_compliance_states",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "intune" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Intune findings."""
        return {
            "raw_event_id": raw.id,
            "source": "intune",
            "source_type": SourceType.MDM,
            "provider": "intune",
            "observed_at": raw.observed_at,
        }

    # -- Managed Devices --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        """Device inventory with compliance, encryption, and OS freshness checks."""
        findings = []
        devices = raw.raw_data.get("records", [])

        for device in devices:
            device_id = device.get("id", "")
            name = device.get("deviceName", "unknown")
            os_name = device.get("operatingSystem", "")
            os_version = device.get("osVersion", "")
            compliance_state = device.get("complianceState", "unknown").lower()
            is_encrypted = device.get("isEncrypted", True)
            model = device.get("model", "")
            manufacturer = device.get("manufacturer", "")
            user_principal = device.get("userPrincipalName", "")
            last_sync = device.get("lastSyncDateTime", "")
            management_agent = device.get("managementAgent", "")

            issues: list[str] = []

            # Non-compliant device
            if compliance_state in ("noncompliant", "conflict", "error", "ingraceperiod"):
                issues.append(f"compliance_{compliance_state}")

            # Unencrypted device
            if not is_encrypted:
                issues.append("device_not_encrypted")

            # Outdated OS check (basic heuristic — flag if osVersion looks old)
            if self._is_outdated_os(os_name, os_version):
                issues.append("outdated_os")

            # Emit inventory finding for every device
            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Intune device: {name} ({os_name} {os_version})",
                detail={
                    "device_id": device_id,
                    "device_name": name,
                    "operating_system": os_name,
                    "os_version": os_version,
                    "compliance_state": compliance_state,
                    "is_encrypted": is_encrypted,
                    "model": model,
                    "manufacturer": manufacturer,
                    "user_principal_name": user_principal,
                    "last_sync_date_time": last_sync,
                    "management_agent": management_agent,
                },
                resource_id=device_id,
                resource_type="mdm_device",
                resource_name=name,
                severity="info",
            ))

            # Non-compliant -> policy_violation
            if compliance_state in ("noncompliant", "conflict", "error"):
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title=f"Non-compliant device: {name} (state: {compliance_state})",
                    detail={
                        "device_id": device_id,
                        "device_name": name,
                        "compliance_state": compliance_state,
                        "operating_system": os_name,
                        "os_version": os_version,
                        "user_principal_name": user_principal,
                        "issue": "device_non_compliant",
                    },
                    resource_id=device_id,
                    resource_type="mdm_device",
                    resource_name=name,
                    severity="high",
                ))

            # Unencrypted -> misconfiguration
            if not is_encrypted:
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"Unencrypted device: {name}",
                    detail={
                        "device_id": device_id,
                        "device_name": name,
                        "is_encrypted": False,
                        "operating_system": os_name,
                        "user_principal_name": user_principal,
                        "issue": "device_not_encrypted",
                    },
                    resource_id=device_id,
                    resource_type="mdm_device",
                    resource_name=name,
                    severity="high",
                ))

            # Outdated OS -> misconfiguration
            if self._is_outdated_os(os_name, os_version):
                findings.append(FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"Outdated OS on device: {name} ({os_name} {os_version})",
                    detail={
                        "device_id": device_id,
                        "device_name": name,
                        "operating_system": os_name,
                        "os_version": os_version,
                        "user_principal_name": user_principal,
                        "issue": "outdated_os",
                    },
                    resource_id=device_id,
                    resource_type="mdm_device",
                    resource_name=name,
                    severity="medium",
                ))

        return findings

    # -- Compliance Policies --

    def _normalize_compliance_policies(self, raw: RawEventData) -> list[FindingData]:
        """Policy inventory — one finding per compliance policy."""
        findings = []
        policies = raw.raw_data.get("records", [])

        for policy in policies:
            policy_id = policy.get("id", "")
            name = policy.get("displayName", "unknown")
            description = policy.get("description", "")
            created = policy.get("createdDateTime", "")
            last_modified = policy.get("lastModifiedDateTime", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Intune compliance policy: {name}",
                detail={
                    "policy_id": policy_id,
                    "display_name": name,
                    "description": description,
                    "created_date_time": created,
                    "last_modified_date_time": last_modified,
                },
                resource_id=policy_id,
                resource_type="mdm_policy",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- Compliance States --

    def _normalize_compliance_states(self, raw: RawEventData) -> list[FindingData]:
        """Per-device compliance state. Non-compliant -> policy_violation."""
        findings = []
        states = raw.raw_data.get("records", [])

        for state in states:
            state_id = state.get("id", "")
            device_id = state.get("deviceId", state.get("managedDeviceId", ""))
            display_name = state.get("displayName", state.get("settingName", "unknown"))
            compliance = state.get("state", state.get("complianceState", "unknown")).lower()
            policy_name = state.get("policyName", state.get("displayName", ""))
            user_principal = state.get("userPrincipalName", "")

            obs_type = "inventory"
            severity = "info"

            if compliance in ("noncompliant", "conflict", "error"):
                obs_type = "policy_violation"
                severity = "high"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=(
                    f"Compliance state: {display_name} — {compliance}"
                    + (f" (policy: {policy_name})" if policy_name else "")
                ),
                detail={
                    "state_id": state_id,
                    "device_id": device_id,
                    "display_name": display_name,
                    "compliance_state": compliance,
                    "policy_name": policy_name,
                    "user_principal_name": user_principal,
                },
                resource_id=device_id or state_id,
                resource_type="mdm_compliance_state",
                resource_name=display_name,
                severity=severity,
            ))

        return findings

    # -- Helpers --

    @staticmethod
    def _is_outdated_os(os_name: str, os_version: str) -> bool:
        """Heuristic check for outdated OS versions.

        This is intentionally conservative — flags obviously old major versions.
        Real deployments should use compliance policies for precise version checks.
        """
        os_lower = os_name.lower()
        if not os_version:
            return False

        try:
            major = int(os_version.split(".")[0])
        except (ValueError, IndexError):
            return False

        # Windows: flag anything below Windows 10 (major version 10)
        if "windows" in os_lower and major < 10:
            return True

        # macOS: flag anything below 13 (Ventura)
        if "mac" in os_lower and major < 13:
            return True

        # iOS: flag anything below 16
        if "ios" in os_lower and major < 16:
            return True

        # Android: flag anything below 13
        if "android" in os_lower and major < 13:
            return True

        return False


# Register
registry.register(IntuneNormalizer())
