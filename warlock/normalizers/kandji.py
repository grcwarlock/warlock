"""Kandji normalizer — transforms raw Kandji API responses into Findings.

Handles devices, blueprints, library items, and users.
Flags: unencrypted devices, outdated OS, firewall disabled, missing blueprints.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class KandjiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "kandji_devices": "_normalize_devices",
        "kandji_blueprints": "_normalize_blueprints",
        "kandji_library_items": "_normalize_library_items",
        "kandji_users": "_normalize_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "kandji" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Kandji findings."""
        return {
            "raw_event_id": raw.id,
            "source": "kandji",
            "source_type": SourceType.MDM,
            "provider": "kandji",
            "observed_at": raw.observed_at,
        }

    # -- Devices --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        """Inventory devices; flag unencrypted, outdated OS, firewall disabled, missing blueprints."""
        findings = []
        devices = raw.raw_data.get("devices", [])

        for device in devices:
            device_id = device.get("device_id", device.get("id", ""))
            device_name = device.get("device_name", device.get("name", ""))
            serial = device.get("serial_number", "")
            model = device.get("model", "")
            os_version = device.get("os_version", "")
            platform = device.get("platform", "")
            filevault_enabled = device.get(
                "filevault_enabled", device.get("is_filevault_enabled", None)
            )
            firewall_enabled = device.get(
                "firewall_enabled", device.get("is_firewall_enabled", None)
            )
            blueprint_id = device.get("blueprint_id", "")
            blueprint_name = device.get("blueprint_name", "")
            last_check_in = device.get("last_check_in", device.get("last_seen", ""))
            is_missing = device.get("is_missing", False)

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Kandji device: {device_name} ({model})",
                    detail={
                        "device_id": str(device_id),
                        "device_name": device_name,
                        "serial_number": serial,
                        "model": model,
                        "os_version": os_version,
                        "platform": platform,
                        "filevault_enabled": filevault_enabled,
                        "firewall_enabled": firewall_enabled,
                        "blueprint_id": str(blueprint_id),
                        "blueprint_name": blueprint_name,
                        "last_check_in": last_check_in,
                        "is_missing": is_missing,
                    },
                    resource_id=str(device_id),
                    resource_type="kandji_device",
                    resource_name=device_name or serial,
                    severity="info",
                )
            )

            # Flag unencrypted devices (FileVault disabled)
            if filevault_enabled is False:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Device disk not encrypted: {device_name}",
                        detail={
                            "device_id": str(device_id),
                            "device_name": device_name,
                            "serial_number": serial,
                            "filevault_enabled": False,
                            "issue": "FileVault is disabled — device disk is not encrypted, data at rest is unprotected",
                        },
                        resource_id=str(device_id),
                        resource_type="kandji_device",
                        resource_name=device_name or serial,
                        severity="high",
                    )
                )

            # Flag firewall disabled
            if firewall_enabled is False:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Firewall disabled on device: {device_name}",
                        detail={
                            "device_id": str(device_id),
                            "device_name": device_name,
                            "serial_number": serial,
                            "firewall_enabled": False,
                            "issue": "macOS firewall is disabled — device accepts inbound network connections without filtering",
                        },
                        resource_id=str(device_id),
                        resource_type="kandji_device",
                        resource_name=device_name or serial,
                        severity="high",
                    )
                )

            # Flag outdated OS (macOS < 14 or iOS < 17 as heuristic)
            if os_version:
                try:
                    major = int(os_version.split(".")[0])
                    is_outdated = False
                    if (
                        (platform and "mac" in platform.lower() and major < 14)
                        or (platform and "ios" in platform.lower() and major < 17)
                        or (platform and "ipados" in platform.lower() and major < 17)
                    ):
                        is_outdated = True

                    if is_outdated:
                        findings.append(
                            FindingData(
                                **self._base(raw),
                                observation_type="misconfiguration",
                                title=f"Outdated OS on device: {device_name} ({os_version})",
                                detail={
                                    "device_id": str(device_id),
                                    "device_name": device_name,
                                    "os_version": os_version,
                                    "platform": platform,
                                    "issue": f"Device is running outdated OS version {os_version} — missing security patches",
                                },
                                resource_id=str(device_id),
                                resource_type="kandji_device",
                                resource_name=device_name or serial,
                                severity="medium",
                            )
                        )
                except (ValueError, IndexError):
                    pass  # Cannot parse OS version — skip check

            # Flag devices without a blueprint
            if not blueprint_id:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Device without blueprint assignment: {device_name}",
                        detail={
                            "device_id": str(device_id),
                            "device_name": device_name,
                            "serial_number": serial,
                            "blueprint_id": "",
                            "issue": "Device has no blueprint assigned — no MDM configuration profile is enforced",
                        },
                        resource_id=str(device_id),
                        resource_type="kandji_device",
                        resource_name=device_name or serial,
                        severity="high",
                    )
                )

        return findings

    # -- Blueprints --

    def _normalize_blueprints(self, raw: RawEventData) -> list[FindingData]:
        """Inventory blueprints."""
        findings = []
        blueprints = raw.raw_data.get("blueprints", [])

        for bp in blueprints:
            bp_id = bp.get("id", bp.get("blueprint_id", ""))
            bp_name = bp.get("name", "")
            enrollment_code = bp.get("enrollment_code", {})
            is_active = (
                enrollment_code.get("is_active", True)
                if isinstance(enrollment_code, dict)
                else True
            )

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Kandji blueprint: {bp_name}",
                    detail={
                        "blueprint_id": str(bp_id),
                        "blueprint_name": bp_name,
                        "is_active": is_active,
                    },
                    resource_id=str(bp_id),
                    resource_type="kandji_blueprint",
                    resource_name=bp_name,
                    severity="info",
                )
            )

        return findings

    # -- Library Items --

    def _normalize_library_items(self, raw: RawEventData) -> list[FindingData]:
        """Inventory library items."""
        findings = []
        items = raw.raw_data.get("library_items", [])

        for item in items:
            item_id = item.get("id", "")
            item_name = item.get("name", "")
            item_type = item.get("type", item.get("item_type", ""))
            active = item.get("active", True)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Kandji library item: {item_name} ({item_type})",
                    detail={
                        "item_id": str(item_id),
                        "item_name": item_name,
                        "item_type": item_type,
                        "active": active,
                    },
                    resource_id=str(item_id),
                    resource_type="kandji_library_item",
                    resource_name=item_name,
                    severity="info",
                )
            )

        return findings

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Kandji users."""
        findings = []
        users = raw.raw_data.get("users", [])

        for user in users:
            user_id = user.get("id", user.get("user_id", ""))
            user_name = user.get("name", "")
            email = user.get("email", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Kandji user: {user_name}",
                    detail={
                        "user_id": str(user_id),
                        "user_name": user_name,
                        "email": email,
                    },
                    resource_id=str(user_id),
                    resource_type="kandji_user",
                    resource_name=user_name or email,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(KandjiNormalizer())
