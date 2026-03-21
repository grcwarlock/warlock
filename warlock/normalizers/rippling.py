"""Rippling normalizer — transforms raw Rippling API responses into Findings.

Handles employees, devices, apps, and activity logs.
Flags: terminated employees with active devices, unmanaged devices,
apps without SSO, suspicious activity.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class RipplingNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "rippling_employees": "_normalize_employees",
        "rippling_devices": "_normalize_devices",
        "rippling_apps": "_normalize_apps",
        "rippling_activity": "_normalize_activity",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "rippling" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Rippling findings."""
        return {
            "raw_event_id": raw.id,
            "source": "rippling",
            "source_type": SourceType.HRIS,
            "provider": "rippling",
            "observed_at": raw.observed_at,
        }

    # -- Employees --

    def _normalize_employees(self, raw: RawEventData) -> list[FindingData]:
        """Inventory employees; flag terminated with active devices."""
        findings = []
        employees = raw.raw_data.get("employees", [])

        for emp in employees:
            emp_id = str(emp.get("id", ""))
            name = emp.get("name", emp.get("display_name", ""))
            email = emp.get("work_email", emp.get("email", ""))
            status = emp.get("employment_status", emp.get("status", ""))
            department = emp.get("department", "")
            devices = emp.get("devices", [])
            start_date = emp.get("start_date", "")
            end_date = emp.get("end_date", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Rippling employee: {name} ({status})",
                    detail={
                        "employee_id": emp_id,
                        "name": name,
                        "email": email,
                        "status": status,
                        "department": department,
                        "device_count": len(devices) if isinstance(devices, list) else 0,
                        "start_date": start_date,
                        "end_date": end_date,
                    },
                    resource_id=emp_id,
                    resource_type="rippling_employee",
                    resource_name=name or email,
                    severity="info",
                )
            )

            # Flag terminated employees with assigned devices
            if status in ("terminated", "inactive") and devices:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Terminated employee with active devices: {name}",
                        detail={
                            "employee_id": emp_id,
                            "name": name,
                            "status": status,
                            "device_count": len(devices),
                            "devices": devices[:5],
                            "issue": "Terminated employee still has devices assigned — equipment may not be recovered and data may be at risk",
                        },
                        resource_id=emp_id,
                        resource_type="rippling_employee",
                        resource_name=name or email,
                        severity="high",
                    )
                )

        return findings

    # -- Devices --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        """Inventory devices; flag unmanaged devices."""
        findings = []
        devices = raw.raw_data.get("devices", [])

        for device in devices:
            device_id = str(device.get("id", ""))
            device_name = device.get("name", device.get("hostname", ""))
            platform = device.get("platform", device.get("os", ""))
            os_version = device.get("os_version", "")
            mdm_enrolled = device.get("mdm_enrolled", device.get("managed", False))
            encrypted = device.get("disk_encrypted", device.get("encrypted", None))
            owner = device.get("assigned_to", device.get("owner", ""))
            serial = device.get("serial_number", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Rippling device: {device_name} ({platform})",
                    detail={
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "os_version": os_version,
                        "mdm_enrolled": mdm_enrolled,
                        "encrypted": encrypted,
                        "owner": owner,
                        "serial_number": serial,
                    },
                    resource_id=device_id,
                    resource_type="rippling_device",
                    resource_name=device_name or serial,
                    severity="info",
                )
            )

            # Flag unmanaged (not MDM enrolled) devices
            if not mdm_enrolled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Unmanaged device (no MDM): {device_name}",
                        detail={
                            "device_id": device_id,
                            "device_name": device_name,
                            "platform": platform,
                            "mdm_enrolled": False,
                            "owner": owner,
                            "issue": "Device is not enrolled in MDM — security policies, remote wipe, and compliance checks cannot be enforced",
                        },
                        resource_id=device_id,
                        resource_type="rippling_device",
                        resource_name=device_name or serial,
                        severity="high",
                    )
                )

            # Flag unencrypted devices
            if encrypted is False:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Device missing disk encryption: {device_name}",
                        detail={
                            "device_id": device_id,
                            "device_name": device_name,
                            "platform": platform,
                            "encrypted": False,
                            "issue": "Device disk is not encrypted — data at rest is unprotected",
                        },
                        resource_id=device_id,
                        resource_type="rippling_device",
                        resource_name=device_name or serial,
                        severity="high",
                    )
                )

        return findings

    # -- Apps --

    def _normalize_apps(self, raw: RawEventData) -> list[FindingData]:
        """Inventory apps; flag apps without SSO."""
        findings = []
        apps = raw.raw_data.get("apps", [])

        for app in apps:
            app_id = str(app.get("id", ""))
            app_name = app.get("name", "")
            sso_enabled = app.get("sso_enabled", app.get("saml_enabled", False))
            provisioning = app.get("provisioning_enabled", False)
            user_count = app.get("user_count", 0)
            category = app.get("category", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Rippling app: {app_name} (SSO={'enabled' if sso_enabled else 'disabled'})",
                    detail={
                        "app_id": app_id,
                        "app_name": app_name,
                        "sso_enabled": sso_enabled,
                        "provisioning_enabled": provisioning,
                        "user_count": user_count,
                        "category": category,
                    },
                    resource_id=app_id,
                    resource_type="rippling_app",
                    resource_name=app_name,
                    severity="info",
                )
            )

            # Flag apps without SSO
            if not sso_enabled:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"App without SSO: {app_name}",
                        detail={
                            "app_id": app_id,
                            "app_name": app_name,
                            "sso_enabled": False,
                            "user_count": user_count,
                            "issue": "Application is not using SSO — credentials are managed outside of identity provider, increasing risk of unauthorized access",
                        },
                        resource_id=app_id,
                        resource_type="rippling_app",
                        resource_name=app_name,
                        severity="medium",
                    )
                )

        return findings

    # -- Activity --

    def _normalize_activity(self, raw: RawEventData) -> list[FindingData]:
        """Flag suspicious activity from audit logs."""
        findings = []
        logs = raw.raw_data.get("logs", [])

        suspicious_actions = {
            "admin_role_change", "permission_escalation", "bulk_delete",
            "api_key_created", "sso_disabled", "mfa_disabled",
        }

        for entry in logs:
            log_id = str(entry.get("id", ""))
            action = entry.get("action", "")
            actor = entry.get("actor", entry.get("performed_by", ""))
            target = entry.get("target", "")
            timestamp = entry.get("timestamp", entry.get("created_at", ""))
            ip_address = entry.get("ip_address", "")

            if action in suspicious_actions:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Suspicious activity: {action} by {actor}",
                        detail={
                            "log_id": log_id,
                            "action": action,
                            "actor": actor,
                            "target": target,
                            "timestamp": timestamp,
                            "ip_address": ip_address,
                            "issue": f"Suspicious administrative action '{action}' detected — review for unauthorized changes",
                        },
                        resource_id=log_id,
                        resource_type="rippling_activity",
                        resource_name=f"{action}:{actor}",
                        severity="high",
                    )
                )

        return findings


# Register
registry.register(RipplingNormalizer())
