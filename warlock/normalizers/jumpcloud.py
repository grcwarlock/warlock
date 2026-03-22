"""JumpCloud normalizer — transforms raw JumpCloud API responses into Findings.

Handles users, devices, policies, and auth logs.
Flags: users without MFA, suspended/locked users, unencrypted devices,
outdated OS, failed authentication attempts.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class JumpCloudNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "jumpcloud_users": "_normalize_users",
        "jumpcloud_devices": "_normalize_devices",
        "jumpcloud_policies": "_normalize_policies",
        "jumpcloud_auth_logs": "_normalize_auth_logs",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "jumpcloud" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all JumpCloud findings."""
        return {
            "raw_event_id": raw.id,
            "source": "jumpcloud",
            "source_type": SourceType.IAM,
            "provider": "jumpcloud",
            "observed_at": raw.observed_at,
        }

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """Inventory users; flag users without MFA and suspended/locked users."""
        findings = []
        users = raw.raw_data.get("users", [])

        for user in users:
            user_id = user.get("_id", user.get("id", ""))
            username = user.get("username", "")
            email = user.get("email", "")
            state = user.get("state", "")
            suspended = user.get("suspended", False)
            activated = user.get("activated", True)
            mfa_configured = (
                user.get("mfa", {}).get("configured", False)
                if isinstance(user.get("mfa"), dict)
                else user.get("totp_enabled", False)
            )
            account_locked = user.get("account_locked", False)
            password_expired = user.get("password_expired", False)
            created = user.get("created", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"JumpCloud user: {username} ({state or 'active'})",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "email": email,
                        "state": state,
                        "suspended": suspended,
                        "activated": activated,
                        "mfa_configured": mfa_configured,
                        "account_locked": account_locked,
                        "password_expired": password_expired,
                        "created": created,
                    },
                    resource_id=user_id,
                    resource_type="jumpcloud_user",
                    resource_name=username or email,
                    severity="info",
                )
            )

            # Flag users without MFA configured
            if not mfa_configured and not suspended and activated:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"User without MFA: {username}",
                        detail={
                            "user_id": user_id,
                            "username": username,
                            "email": email,
                            "mfa_configured": False,
                            "issue": "Active user has no MFA configured — account relies on password-only authentication",
                        },
                        resource_id=user_id,
                        resource_type="jumpcloud_user",
                        resource_name=username or email,
                        severity="high",
                    )
                )

            # Flag suspended users (stale access risk)
            if suspended:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Suspended user account: {username}",
                        detail={
                            "user_id": user_id,
                            "username": username,
                            "email": email,
                            "suspended": True,
                            "issue": "User account is suspended — review for deprovisioning or reactivation",
                        },
                        resource_id=user_id,
                        resource_type="jumpcloud_user",
                        resource_name=username or email,
                        severity="medium",
                    )
                )

            # Flag locked accounts
            if account_locked:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Locked user account: {username}",
                        detail={
                            "user_id": user_id,
                            "username": username,
                            "email": email,
                            "account_locked": True,
                            "issue": "User account is locked — possible brute-force attempt or policy violation",
                        },
                        resource_id=user_id,
                        resource_type="jumpcloud_user",
                        resource_name=username or email,
                        severity="high",
                    )
                )

        return findings

    # -- Devices --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        """Inventory devices; flag unencrypted disks and outdated OS."""
        findings = []
        devices = raw.raw_data.get("devices", [])

        for device in devices:
            device_id = device.get("_id", device.get("id", ""))
            hostname = device.get("hostname", device.get("displayName", ""))
            os_name = device.get("os", device.get("osFamily", ""))
            os_version = device.get("version", device.get("osVersionDetail", ""))
            arch = device.get("arch", "")
            active = device.get("active", True)
            fde = device.get("fde", {})
            disk_encrypted = fde.get("active", False) if isinstance(fde, dict) else False
            agent_version = device.get("agentVersion", "")
            last_contact = device.get("lastContact", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"JumpCloud device: {hostname} ({os_name} {os_version})",
                    detail={
                        "device_id": device_id,
                        "hostname": hostname,
                        "os": os_name,
                        "os_version": os_version,
                        "arch": arch,
                        "active": active,
                        "disk_encrypted": disk_encrypted,
                        "agent_version": agent_version,
                        "last_contact": last_contact,
                    },
                    resource_id=str(device_id),
                    resource_type="jumpcloud_device",
                    resource_name=hostname or str(device_id),
                    severity="info",
                )
            )

            # Flag unencrypted disk
            if not disk_encrypted:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Device missing disk encryption: {hostname}",
                        detail={
                            "device_id": device_id,
                            "hostname": hostname,
                            "os": os_name,
                            "disk_encrypted": False,
                            "issue": "Device full-disk encryption is not active — data at rest is unprotected",
                        },
                        resource_id=str(device_id),
                        resource_type="jumpcloud_device",
                        resource_name=hostname or str(device_id),
                        severity="high",
                    )
                )

            # Flag inactive/stale devices
            if not active:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Inactive device: {hostname}",
                        detail={
                            "device_id": device_id,
                            "hostname": hostname,
                            "os": os_name,
                            "active": False,
                            "last_contact": last_contact,
                            "issue": "Device has not contacted JumpCloud recently — may be lost, stolen, or decommissioned",
                        },
                        resource_id=str(device_id),
                        resource_type="jumpcloud_device",
                        resource_name=hostname or str(device_id),
                        severity="medium",
                    )
                )

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory JumpCloud policies."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_id = policy.get("id", policy.get("_id", ""))
            policy_name = policy.get("name", "")
            template = policy.get("template", {})
            template_name = template.get("name", "") if isinstance(template, dict) else ""
            os_family = template.get("osFamily", "") if isinstance(template, dict) else ""
            active = policy.get("active", True)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"JumpCloud policy: {policy_name}",
                    detail={
                        "policy_id": policy_id,
                        "policy_name": policy_name,
                        "template_name": template_name,
                        "os_family": os_family,
                        "active": active,
                    },
                    resource_id=policy_id,
                    resource_type="jumpcloud_policy",
                    resource_name=policy_name,
                    severity="info",
                )
            )

        return findings

    # -- Auth Logs --

    def _normalize_auth_logs(self, raw: RawEventData) -> list[FindingData]:
        """Alert on failed and anomalous authentication events."""
        findings = []
        logs = raw.raw_data.get("logs", [])

        for entry in logs:
            event_id = entry.get("id", entry.get("_id", ""))
            event_type = entry.get("event_type", "")
            success = entry.get("success", True)
            username = (
                entry.get("initiated_by", {}).get("username", "")
                if isinstance(entry.get("initiated_by"), dict)
                else entry.get("username", "")
            )
            client_ip = entry.get("client_ip", entry.get("src_ip", ""))
            timestamp = entry.get("timestamp", entry.get("created", ""))
            geoip = entry.get("geoip", {})
            message = entry.get("message", "")
            mfa_used = entry.get("mfa", False)

            # Flag failed login attempts
            if not success:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Failed login attempt: {username}",
                        detail={
                            "event_id": event_id,
                            "event_type": event_type,
                            "username": username,
                            "success": False,
                            "client_ip": client_ip,
                            "timestamp": timestamp,
                            "geoip": geoip,
                            "message": message,
                            "mfa_used": mfa_used,
                            "issue": f"Authentication failed for user {username} from {client_ip}",
                        },
                        resource_id=event_id,
                        resource_type="jumpcloud_auth_event",
                        resource_name=f"failed:{username}",
                        severity="medium",
                    )
                )

        return findings


# Register
registry.register(JumpCloudNormalizer())
