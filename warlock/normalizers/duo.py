"""Duo Security normalizer — transforms raw Duo Admin API responses into Findings.

Handles users, auth logs, devices, and policies.
Flags: users without MFA enrolled, auth fraud events, bypass-status users,
unhealthy devices (no screen lock, jailbroken).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class DuoNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "duo_users": "_normalize_users",
        "duo_auth_logs": "_normalize_auth_logs",
        "duo_devices": "_normalize_devices",
        "duo_policies": "_normalize_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "duo" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Duo findings."""
        return {
            "raw_event_id": raw.id,
            "source": "duo",
            "source_type": SourceType.IAM,
            "provider": "duo",
            "observed_at": raw.observed_at,
        }

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """Inventory users; flag users without MFA and bypass-status users."""
        findings = []
        users = raw.raw_data.get("users", [])

        for user in users:
            user_id = user.get("user_id", "")
            username = user.get("username", "")
            email = user.get("email", "")
            status = user.get("status", "")
            is_enrolled = user.get("is_enrolled", False)
            phones = user.get("phones", [])
            tokens = user.get("tokens", [])
            last_login = user.get("last_login", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Duo user: {username} ({status})",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "email": email,
                        "status": status,
                        "is_enrolled": is_enrolled,
                        "phone_count": len(phones),
                        "token_count": len(tokens),
                        "last_login": last_login,
                    },
                    resource_id=user_id,
                    resource_type="duo_user",
                    resource_name=username or email,
                    severity="info",
                )
            )

            # Flag users not enrolled in MFA
            if not is_enrolled and status == "active":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"User not enrolled in MFA: {username}",
                        detail={
                            "user_id": user_id,
                            "username": username,
                            "email": email,
                            "status": status,
                            "is_enrolled": False,
                            "issue": "Active user has not enrolled in MFA — account is unprotected by second factor",
                        },
                        resource_id=user_id,
                        resource_type="duo_user",
                        resource_name=username or email,
                        severity="high",
                    )
                )

            # Flag bypass-status users
            if status == "bypass":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"User in bypass status: {username}",
                        detail={
                            "user_id": user_id,
                            "username": username,
                            "email": email,
                            "status": "bypass",
                            "issue": "User is set to bypass MFA — all authentication skips second factor verification",
                        },
                        resource_id=user_id,
                        resource_type="duo_user",
                        resource_name=username or email,
                        severity="critical",
                    )
                )

        return findings

    # -- Auth Logs --

    def _normalize_auth_logs(self, raw: RawEventData) -> list[FindingData]:
        """Alert on fraud and failed auth events."""
        findings = []
        logs = raw.raw_data.get("logs", [])

        for entry in logs:
            txid = entry.get("txid", entry.get("access_device", {}).get("ip", ""))
            result = entry.get("result", "")
            reason = entry.get("reason", "")
            username = (
                entry.get("user", {}).get("name", "")
                if isinstance(entry.get("user"), dict)
                else entry.get("user", "")
            )
            factor = entry.get("factor", "")
            timestamp = entry.get("timestamp", "")
            entry.get("event_type", "")
            access_device = entry.get("access_device", {})

            # Flag fraud events
            if result == "fraud" or reason == "user_marked_fraud":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"MFA fraud reported by {username}",
                        detail={
                            "txid": txid,
                            "username": username,
                            "result": result,
                            "reason": reason,
                            "factor": factor,
                            "timestamp": timestamp,
                            "access_device_ip": access_device.get("ip", ""),
                            "access_device_location": access_device.get("location", {}),
                            "issue": "User reported authentication attempt as fraudulent — potential account compromise",
                        },
                        resource_id=txid,
                        resource_type="duo_auth_event",
                        resource_name=f"fraud:{username}",
                        severity="critical",
                    )
                )

            # Flag denied/failed attempts
            elif result == "denied":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"MFA auth denied for {username}: {reason}",
                        detail={
                            "txid": txid,
                            "username": username,
                            "result": result,
                            "reason": reason,
                            "factor": factor,
                            "timestamp": timestamp,
                            "access_device_ip": access_device.get("ip", ""),
                            "issue": f"Authentication denied: {reason}",
                        },
                        resource_id=txid,
                        resource_type="duo_auth_event",
                        resource_name=f"denied:{username}",
                        severity="medium",
                    )
                )

        return findings

    # -- Devices --

    def _normalize_devices(self, raw: RawEventData) -> list[FindingData]:
        """Inventory devices; flag unhealthy endpoints."""
        findings = []
        devices = raw.raw_data.get("devices", [])

        for device in devices:
            device_id = device.get("epkey", device.get("device_id", ""))
            device_name = device.get("device_name", device.get("model", ""))
            platform = device.get("os_family", device.get("platform", ""))
            os_version = device.get("os_version", "")
            is_encrypted = device.get("disk_encrypted", device.get("full_disk_encryption", None))
            has_screen_lock = device.get("screen_lock", None)
            is_jailbroken = device.get("jailbroken", device.get("tampered", None))
            device.get("health", {})

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Duo endpoint: {device_name} ({platform} {os_version})",
                    detail={
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "os_version": os_version,
                        "disk_encrypted": is_encrypted,
                        "screen_lock": has_screen_lock,
                        "jailbroken": is_jailbroken,
                    },
                    resource_id=str(device_id),
                    resource_type="duo_endpoint",
                    resource_name=device_name or str(device_id),
                    severity="info",
                )
            )

            # Flag no screen lock
            if has_screen_lock is False:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Endpoint missing screen lock: {device_name}",
                        detail={
                            "device_id": device_id,
                            "device_name": device_name,
                            "platform": platform,
                            "screen_lock": False,
                            "issue": "Device has no screen lock configured — physical access bypasses authentication",
                        },
                        resource_id=str(device_id),
                        resource_type="duo_endpoint",
                        resource_name=device_name or str(device_id),
                        severity="high",
                    )
                )

            # Flag jailbroken / tampered devices
            if is_jailbroken in ("Yes", True, "true"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Jailbroken/rooted device detected: {device_name}",
                        detail={
                            "device_id": device_id,
                            "device_name": device_name,
                            "platform": platform,
                            "jailbroken": is_jailbroken,
                            "issue": "Device is jailbroken/rooted — OS security controls are bypassed",
                        },
                        resource_id=str(device_id),
                        resource_type="duo_endpoint",
                        resource_name=device_name or str(device_id),
                        severity="critical",
                    )
                )

            # Flag missing disk encryption
            if is_encrypted is False:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Endpoint missing disk encryption: {device_name}",
                        detail={
                            "device_id": device_id,
                            "device_name": device_name,
                            "platform": platform,
                            "disk_encrypted": False,
                            "issue": "Device disk is not encrypted — data at rest is unprotected",
                        },
                        resource_id=str(device_id),
                        resource_type="duo_endpoint",
                        resource_name=device_name or str(device_id),
                        severity="high",
                    )
                )

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory Duo policies."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        for policy in policies:
            policy_key = policy.get("policy_key", policy.get("key", ""))
            policy_name = policy.get("policy_name", policy.get("name", ""))
            sections = policy.get("sections", {})

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Duo policy: {policy_name}",
                    detail={
                        "policy_key": policy_key,
                        "policy_name": policy_name,
                        "sections": list(sections.keys()) if isinstance(sections, dict) else [],
                    },
                    resource_id=policy_key,
                    resource_type="duo_policy",
                    resource_name=policy_name,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(DuoNormalizer())
