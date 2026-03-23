"""Salesforce normalizer — transforms raw Salesforce API responses into Findings.

Normalizes user accounts (as inventory), profiles (as inventory), and login
history (as access_anomaly when login status is not success).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SalesforceNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "salesforce_users": "_normalize_users",
        "salesforce_profiles": "_normalize_profiles",
        "salesforce_login_history": "_normalize_login_history",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "salesforce" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "salesforce",
            "source_type": SourceType.COLLABORATION,
            "provider": "salesforce",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for user in items:
            user_id = str(user.get("Id", ""))
            username = user.get("Username", "unknown")
            name = user.get("Name", "unknown")
            is_active = user.get("IsActive", True)
            last_login = user.get("LastLoginDate", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Salesforce user: {username}",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "name": name,
                        "is_active": is_active,
                        "last_login_date": last_login,
                        "created_date": user.get("CreatedDate", ""),
                        "email": user.get("Email", ""),
                    },
                    resource_id=user_id,
                    resource_type="salesforce_user",
                    resource_name=username,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_profiles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for profile in items:
            profile_id = str(profile.get("Id", ""))
            name = profile.get("Name", "unknown")
            user_type = profile.get("UserType", "")
            description = profile.get("Description", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Salesforce profile: {name}",
                    detail={
                        "profile_id": profile_id,
                        "name": name,
                        "user_type": user_type,
                        "description": description,
                    },
                    resource_id=profile_id,
                    resource_type="salesforce_profile",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_login_history(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for entry in items:
            record_id = str(entry.get("Id", ""))
            user_id = str(entry.get("UserId", ""))
            status = entry.get("Status", "Success")
            login_type = entry.get("LoginType", "")
            source_ip = entry.get("SourceIp", "")
            login_time = entry.get("LoginTime", "")

            # Failed logins are access anomalies; successes are inventory
            is_failed = status.lower() not in ("success", "")
            obs_type = "access_anomaly" if is_failed else "inventory"
            severity = "medium" if is_failed else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Salesforce login {status}: user {user_id}",
                    detail={
                        "record_id": record_id,
                        "user_id": user_id,
                        "status": status,
                        "login_type": login_type,
                        "source_ip": source_ip,
                        "login_time": login_time,
                    },
                    resource_id=record_id,
                    resource_type="salesforce_login",
                    resource_name=user_id,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(SalesforceNormalizer())
