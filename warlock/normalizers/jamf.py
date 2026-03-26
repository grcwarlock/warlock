"""Jamf normalizer — transforms raw Jamf Pro API responses into Findings.

Handles managed devices, policies, configuration profiles, and patch reports.
Flags: devices without FileVault, outdated OS, missing critical patches,
devices not checked in >7 days.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Minimum acceptable macOS version for compliance
MIN_MACOS_VERSION = "14.0"

# Days without check-in before flagging stale
STALE_CHECKIN_DAYS = 7


class JamfNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "jamf_devices": "_normalize_devices",
        "jamf_policies": "_normalize_policies",
        "jamf_config_profiles": "_normalize_config_profiles",
        "jamf_patch_reports": "_normalize_patch_reports",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "jamf" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Jamf findings."""
        return {
            "raw_event_id": raw.id,
            "source": "jamf",
            "source_type": SourceType.MDM,
            "provider": "jamf",
            "observed_at": raw.observed_at,
        }

    # -- Devices --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        """Inventory devices; flag missing FileVault, outdated OS, stale check-in."""
        findings = []
        devices = raw.raw_data.get("devices", [])

        for device in devices:
            device_id = str(device.get("id", ""))
            general = device.get("general", {})
            hardware = device.get("hardware", {})
            security = device.get("security", {})
            os_version = device.get("operatingSystem", {})

            name = general.get("name", "")
            serial = hardware.get("serialNumber", general.get("serialNumber", ""))
            managed = general.get("managementStatus", {}).get("enrolled", True)
            last_contact = general.get("lastContactTime", "")
            os_ver = os_version.get("version", hardware.get("osVersion", ""))
            filevault_enabled = security.get("fileVault2Status", "") in (
                "ALL_ENCRYPTED",
                "BOOT_ENCRYPTED",
            )

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Managed device: {name} ({serial})",
                    detail={
                        "device_id": device_id,
                        "name": name,
                        "serial_number": serial,
                        "os_version": os_ver,
                        "managed": managed,
                        "filevault_enabled": filevault_enabled,
                        "last_contact": last_contact,
                    },
                    resource_id=device_id,
                    resource_type="jamf_managed_device",
                    resource_name=name or serial,
                    severity="info",
                )
            )

            # Flag missing FileVault
            if not filevault_enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Device missing FileVault encryption: {name}",
                        detail={
                            "device_id": device_id,
                            "name": name,
                            "serial_number": serial,
                            "filevault_status": security.get("fileVault2Status", "UNKNOWN"),
                            "issue": "Full-disk encryption (FileVault) is not enabled — data at rest is unprotected",
                        },
                        resource_id=device_id,
                        resource_type="jamf_managed_device",
                        resource_name=name or serial,
                        severity="high",
                    )
                )

            # Flag outdated OS
            if os_ver and self._version_lt(os_ver, MIN_MACOS_VERSION):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Device running outdated macOS: {name} ({os_ver})",
                        detail={
                            "device_id": device_id,
                            "name": name,
                            "os_version": os_ver,
                            "minimum_required": MIN_MACOS_VERSION,
                            "issue": f"macOS {os_ver} is below minimum required version {MIN_MACOS_VERSION}",
                        },
                        resource_id=device_id,
                        resource_type="jamf_managed_device",
                        resource_name=name or serial,
                        severity="medium",
                    )
                )

            # Flag stale check-in (>7 days)
            if last_contact:
                try:
                    contact_dt = datetime.fromisoformat(last_contact.replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) - contact_dt > timedelta(days=STALE_CHECKIN_DAYS):
                        days_ago = (datetime.now(timezone.utc) - contact_dt).days
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="alert",
                                title=f"Device not checked in for {days_ago} days: {name}",
                                detail={
                                    "device_id": device_id,
                                    "name": name,
                                    "last_contact": last_contact,
                                    "days_since_contact": days_ago,
                                    "threshold_days": STALE_CHECKIN_DAYS,
                                    "issue": f"Device has not contacted Jamf in {days_ago} days — may be lost, stolen, or non-compliant",
                                },
                                resource_id=device_id,
                                resource_type="jamf_managed_device",
                                resource_name=name or serial,
                                severity="medium",
                            )
                        )
                except (ValueError, TypeError):
                    pass

        return findings

    @staticmethod
    def _version_lt(version: str, minimum: str) -> bool:
        """Compare version strings. Returns True if version < minimum."""
        try:
            v_parts = [int(x) for x in version.split(".")[:3]]
            m_parts = [int(x) for x in minimum.split(".")[:3]]
            # Pad to same length
            while len(v_parts) < 3:
                v_parts.append(0)
            while len(m_parts) < 3:
                m_parts.append(0)
            return v_parts < m_parts
        except (ValueError, TypeError):
            return False

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Jamf policies."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_id = str(policy.get("id", ""))
            policy_name = policy.get("name", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Jamf policy: {policy_name}",
                    detail={
                        "policy_id": policy_id,
                        "name": policy_name,
                    },
                    resource_id=policy_id,
                    resource_type="jamf_policy",
                    resource_name=policy_name,
                    severity="info",
                )
            )

        return findings

    # -- Configuration Profiles --

    def _normalize_config_profiles(self, raw: RawEventData) -> list[FindingData]:
        """Inventory configuration profiles."""
        findings = []
        profiles = raw.raw_data.get("profiles", [])

        for profile in profiles:
            profile_id = str(profile.get("id", ""))
            profile_name = profile.get("name", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Configuration profile: {profile_name}",
                    detail={
                        "profile_id": profile_id,
                        "name": profile_name,
                    },
                    resource_id=profile_id,
                    resource_type="jamf_config_profile",
                    resource_name=profile_name,
                    severity="info",
                )
            )

        return findings

    # -- Patch Reports --

    def _normalize_patch_reports(self, raw: RawEventData) -> list[FindingData]:
        """Inventory patch reports; flag missing critical patches."""
        findings = []
        reports = raw.raw_data.get("reports", [])

        for report in reports:
            report_id = str(report.get("id", ""))
            title = report.get("softwareTitleName", report.get("name", ""))
            total = report.get("totalDevices", 0)
            patched = report.get("upToDate", report.get("patchedDevices", 0))
            unpatched = total - patched if total > patched else 0

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Patch report: {title} ({patched}/{total} patched)",
                    detail={
                        "report_id": report_id,
                        "software_title": title,
                        "total_devices": total,
                        "patched_devices": patched,
                        "unpatched_devices": unpatched,
                    },
                    resource_id=report_id,
                    resource_type="jamf_patch_report",
                    resource_name=title,
                    severity="info",
                )
            )

            # Flag unpatched devices
            if unpatched > 0:
                severity = "high" if unpatched > 10 else "medium"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="vulnerability",
                        title=f"Unpatched devices for {title}: {unpatched}/{total}",
                        detail={
                            "report_id": report_id,
                            "software_title": title,
                            "unpatched_devices": unpatched,
                            "total_devices": total,
                            "issue": f"{unpatched} devices are missing patches for {title}",
                        },
                        resource_id=report_id,
                        resource_type="jamf_patch_report",
                        resource_name=title,
                        severity=severity,
                    )
                )

        return findings


# Register
registry.register(JamfNormalizer())
