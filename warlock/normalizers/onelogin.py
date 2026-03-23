"""OneLogin normalizer — transforms raw OneLogin API responses into Findings.

Normalizes users and roles as inventory findings; events as alerts or
policy_violation findings depending on event type.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# OneLogin event type IDs that represent suspicious/compliance-relevant activity
_POLICY_EVENT_IDS = {
    5,    # User locked out
    6,    # User password changed
    8,    # User MFA disabled
    72,   # App removed from user
    100,  # Role removed from user
}


class OneLoginNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "onelogin_users": "_normalize_users",
        "onelogin_roles": "_normalize_roles",
        "onelogin_events": "_normalize_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "onelogin" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "onelogin",
            "source_type": SourceType.IAM,
            "provider": "onelogin",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for user in items:
            user_id = str(user.get("id", ""))
            username = user.get("username", user.get("email", "unknown"))
            status = user.get("status", 1)
            # Status 1 = active, 2 = suspended, etc.
            locked = user.get("locked_until") is not None

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OneLogin user: {username}",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "firstname": user.get("firstname", ""),
                        "lastname": user.get("lastname", ""),
                        "email": user.get("email", ""),
                        "status": status,
                        "locked": locked,
                        "role_ids": user.get("role_ids", []),
                        "otp_device_count": user.get("otp_device_count", 0),
                    },
                    resource_id=user_id,
                    resource_type="onelogin_user",
                    resource_name=username,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_roles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for role in items:
            role_id = str(role.get("id", ""))
            name = role.get("name", "unknown")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"OneLogin role: {name}",
                    detail={
                        "role_id": role_id,
                        "name": name,
                        "admins": role.get("admins", []),
                        "users": role.get("users", []),
                        "apps": role.get("apps", []),
                    },
                    resource_id=role_id,
                    resource_type="onelogin_role",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for event in items:
            event_id = str(event.get("id", ""))
            event_type_id = event.get("event_type_id", 0)
            actor = event.get("actor_user_name", event.get("user_name", "unknown"))
            event_name = event.get("type", {}).get("name", str(event_type_id)) if isinstance(event.get("type"), dict) else str(event_type_id)

            is_policy = int(event_type_id) in _POLICY_EVENT_IDS
            obs_type = "policy_violation" if is_policy else "alert"
            severity = "medium" if is_policy else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"OneLogin event: {event_name}",
                    detail={
                        "event_id": event_id,
                        "event_type_id": event_type_id,
                        "event_name": event_name,
                        "actor": actor,
                        "user_name": event.get("user_name", ""),
                        "notes": event.get("notes", ""),
                        "created_at": event.get("created_at", ""),
                    },
                    resource_id=event_id,
                    resource_type="onelogin_event",
                    resource_name=event_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(OneLoginNormalizer())
