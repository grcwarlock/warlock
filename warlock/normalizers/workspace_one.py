"""VMware Workspace ONE normalizer — transforms raw UEM API responses into Findings.

Normalizes devices as inventory (non-compliant devices become misconfiguration),
profiles as inventory, and apps as inventory.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class WorkspaceOneNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "workspace_one_devices": "_normalize_devices",
        "workspace_one_profiles": "_normalize_profiles",
        "workspace_one_apps": "_normalize_apps",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "workspace_one" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "workspace_one",
            "source_type": SourceType.MDM,
            "provider": "workspace_one",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for device in items:
            # Workspace ONE uses "Id" as a value object: {"Value": "...", "Type": "Default"}
            id_obj = device.get("Id", {})
            device_id = str(id_obj.get("Value", device.get("DeviceUuid", device.get("id", ""))))
            device_name = device.get("DeviceFriendlyName", device.get("DeviceName", "unknown"))
            platform = device.get("Platform", device.get("OperatingSystem", "unknown"))
            compliance_status = device.get("ComplianceStatus", device.get("Compliant", "Compliant"))

            # Non-compliant or unknown devices are misconfigurations
            is_compliant = str(compliance_status).lower() in ("compliant", "true", "yes", "1")
            obs_type = "misconfiguration" if not is_compliant else "inventory"
            severity = "high" if not is_compliant else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Workspace ONE device: {device_name}",
                    detail={
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "compliance_status": str(compliance_status),
                        "os_version": device.get("OsVersion", ""),
                        "model": device.get("Model", device.get("DeviceModel", "")),
                        "enrollment_status": device.get("EnrollmentStatus", ""),
                        "last_seen": device.get("LastSeen", device.get("LastSyncTime", "")),
                    },
                    resource_id=device_id,
                    resource_type="workspace_one_device",
                    resource_name=device_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_profiles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for profile in items:
            profile_id = str(profile.get("Id", {}).get("Value", profile.get("id", "")))
            name = profile.get("Name", profile.get("name", "unknown"))
            platform = profile.get("Platform", profile.get("platform", "unknown"))
            status = profile.get("Status", profile.get("status", "Active"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Workspace ONE profile: {name}",
                    detail={
                        "profile_id": profile_id,
                        "name": name,
                        "platform": platform,
                        "status": status,
                        "managed_by": profile.get("ManagedBy", ""),
                        "assignment_count": profile.get("AssignedSmartGroups", 0),
                    },
                    resource_id=profile_id,
                    resource_type="workspace_one_profile",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_apps(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for app in items:
            app_id = str(app.get("Id", {}).get("Value", app.get("id", "")))
            name = app.get("ApplicationName", app.get("name", "unknown"))
            platform = app.get("Platform", app.get("platform", "unknown"))
            status = app.get("Status", app.get("status", "Active"))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Workspace ONE app: {name}",
                    detail={
                        "app_id": app_id,
                        "name": name,
                        "platform": platform,
                        "status": status,
                        "version": app.get("AppVersion", app.get("version", "")),
                        "bundle_id": app.get("BundleId", app.get("bundle_id", "")),
                    },
                    resource_id=app_id,
                    resource_type="workspace_one_app",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(WorkspaceOneNormalizer())
