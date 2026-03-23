"""Ping Identity normalizer — transforms raw PingOne API responses into Findings.

Normalizes users and groups as inventory findings; sign-on policies as
policy_violation findings when not compliant.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class PingIdentityNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ping_users": "_normalize_users",
        "ping_groups": "_normalize_groups",
        "ping_sign_on_policies": "_normalize_sign_on_policies",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "ping_identity" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "ping_identity",
            "source_type": SourceType.IAM,
            "provider": "ping_identity",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for user in items:
            user_id = str(user.get("id", ""))
            name = user.get("name", {})
            full_name = (
                f"{name.get('given', '')} {name.get('family', '')}".strip()
                if isinstance(name, dict)
                else str(name)
            )
            username = user.get("username", user.get("email", "unknown"))
            enabled = user.get("enabled", True)
            status = user.get("account", {}).get("status", "OK") if isinstance(user.get("account"), dict) else "OK"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ping Identity user: {username}",
                    detail={
                        "user_id": user_id,
                        "username": username,
                        "full_name": full_name,
                        "enabled": enabled,
                        "status": status,
                        "mfa_enabled": user.get("mfaEnabled", False),
                    },
                    resource_id=user_id,
                    resource_type="ping_user",
                    resource_name=username,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for group in items:
            group_id = str(group.get("id", ""))
            name = group.get("name", "unknown")
            member_count = group.get("memberCount", 0)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Ping Identity group: {name}",
                    detail={
                        "group_id": group_id,
                        "name": name,
                        "description": group.get("description", ""),
                        "member_count": member_count,
                    },
                    resource_id=group_id,
                    resource_type="ping_group",
                    resource_name=name,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_sign_on_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for policy in items:
            policy_id = str(policy.get("id", ""))
            name = policy.get("name", "unknown")
            # Policies lacking MFA actions represent a policy gap
            actions = policy.get("_embedded", {}).get("actions", []) if isinstance(policy.get("_embedded"), dict) else []
            has_mfa_action = any(
                a.get("type", "").upper() in ("MFA", "MULTI_FACTOR_AUTHENTICATION")
                for a in actions
                if isinstance(a, dict)
            )

            obs_type = "policy_violation" if not has_mfa_action else "inventory"
            severity = "medium" if not has_mfa_action else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Ping Identity sign-on policy: {name}",
                    detail={
                        "policy_id": policy_id,
                        "name": name,
                        "description": policy.get("description", ""),
                        "action_count": len(actions),
                        "has_mfa_action": has_mfa_action,
                    },
                    resource_id=policy_id,
                    resource_type="ping_sign_on_policy",
                    resource_name=name,
                    severity=severity,
                    confidence=0.9,
                )
            )

        return findings


# Register
registry.register(PingIdentityNormalizer())
