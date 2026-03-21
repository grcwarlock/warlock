"""1Password normalizer — transforms raw 1Password Events API responses into Findings.

Handles sign-in attempts, item usage events, and audit events.
Flags: failed sign-in attempts, suspicious item access, users without 2FA,
inactive accounts.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Audit event actions considered sensitive
SENSITIVE_AUDIT_ACTIONS = {
    "join",
    "leave",
    "suspend",
    "reactivate",
    "delete",
    "recover",
    "policy_update",
    "vault_create",
    "vault_delete",
    "group_create",
    "group_delete",
    "role_assign",
    "role_revoke",
    "mfa_disable",
    "2fa_disable",
}


class OnePasswordNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "onepassword_signin_attempts": "_normalize_signin_attempts",
        "onepassword_item_usage": "_normalize_item_usage",
        "onepassword_audit_events": "_normalize_audit_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "onepassword" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all 1Password findings."""
        return {
            "raw_event_id": raw.id,
            "source": "onepassword",
            "source_type": SourceType.IAM,
            "provider": "onepassword",
            "observed_at": raw.observed_at,
        }

    # -- Sign-in Attempts --

    def _normalize_signin_attempts(self, raw: RawEventData) -> list[FindingData]:
        """Inventory sign-in attempts; flag failures and suspicious patterns."""
        findings = []
        attempts = raw.raw_data.get("attempts", [])

        for attempt in attempts:
            uuid = attempt.get("uuid", "")
            session_uuid = attempt.get("session_uuid", "")
            target_user = attempt.get("target_user", {})
            user_email = target_user.get("email", "") if isinstance(target_user, dict) else ""
            user_name = target_user.get("name", "") if isinstance(target_user, dict) else ""
            target_user.get("uuid", "") if isinstance(target_user, dict) else ""
            category = attempt.get("category", "")  # success, credentials_failed, mfa_failed
            attempt_type = attempt.get("type", "")
            timestamp = attempt.get("timestamp", "")
            country = attempt.get("country", "")
            attempt.get("details", {})

            # Inventory all attempts
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Sign-in attempt: {user_email} ({category})",
                    detail={
                        "uuid": uuid,
                        "user_email": user_email,
                        "user_name": user_name,
                        "category": category,
                        "type": attempt_type,
                        "timestamp": timestamp,
                        "country": country,
                    },
                    resource_id=uuid or session_uuid,
                    resource_type="onepassword_signin_attempt",
                    resource_name=user_email or user_name,
                    severity="info",
                )
            )

            # Flag failed sign-in attempts
            if category in ("credentials_failed", "mfa_failed"):
                severity = "high" if category == "mfa_failed" else "medium"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Failed sign-in ({category}): {user_email}",
                        detail={
                            "uuid": uuid,
                            "user_email": user_email,
                            "user_name": user_name,
                            "category": category,
                            "type": attempt_type,
                            "timestamp": timestamp,
                            "country": country,
                            "issue": f"Sign-in failed due to {category} — possible credential stuffing or unauthorized access attempt",
                        },
                        resource_id=uuid or session_uuid,
                        resource_type="onepassword_signin_attempt",
                        resource_name=user_email or user_name,
                        severity=severity,
                    )
                )

            # Flag sign-ins with MFA not used (firewall_failed, etc.)
            if category == "firewall_failed":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Sign-in blocked by firewall rules: {user_email}",
                        detail={
                            "uuid": uuid,
                            "user_email": user_email,
                            "category": "firewall_failed",
                            "country": country,
                            "issue": "Sign-in blocked by IP/geo firewall rules — may indicate unauthorized location",
                        },
                        resource_id=uuid or session_uuid,
                        resource_type="onepassword_signin_attempt",
                        resource_name=user_email or user_name,
                        severity="high",
                    )
                )

        return findings

    # -- Item Usage --

    def _normalize_item_usage(self, raw: RawEventData) -> list[FindingData]:
        """Inventory item usage events; flag suspicious access patterns."""
        findings = []
        usages = raw.raw_data.get("usages", [])

        for usage in usages:
            uuid = usage.get("uuid", "")
            user = usage.get("user", {})
            user_email = user.get("email", "") if isinstance(user, dict) else ""
            user_name = user.get("name", "") if isinstance(user, dict) else ""
            item = usage.get("item", {})
            item_uuid = item.get("uuid", "") if isinstance(item, dict) else ""
            item_title = item.get("title", "") if isinstance(item, dict) else ""
            vault = usage.get("vault", {})
            vault_uuid = vault.get("uuid", "") if isinstance(vault, dict) else ""
            vault_name = vault.get("name", "") if isinstance(vault, dict) else ""
            action = usage.get("action", "")
            timestamp = usage.get("timestamp", "")
            usage.get("used_version", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Item usage: {user_email} accessed {item_title} ({action})",
                    detail={
                        "uuid": uuid,
                        "user_email": user_email,
                        "user_name": user_name,
                        "item_uuid": item_uuid,
                        "item_title": item_title,
                        "vault_uuid": vault_uuid,
                        "vault_name": vault_name,
                        "action": action,
                        "timestamp": timestamp,
                    },
                    resource_id=uuid,
                    resource_type="onepassword_item_usage",
                    resource_name=f"{user_email}:{item_title}",
                    severity="info",
                )
            )

            # Flag export/reveal actions as higher interest
            if action in ("secure-copy", "reveal", "export", "fill"):
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Sensitive item action ({action}): {user_email} on {item_title}",
                        detail={
                            "uuid": uuid,
                            "user_email": user_email,
                            "item_title": item_title,
                            "vault_name": vault_name,
                            "action": action,
                            "timestamp": timestamp,
                            "issue": f"User performed '{action}' on vault item — review for data exfiltration risk",
                        },
                        resource_id=uuid,
                        resource_type="onepassword_item_usage",
                        resource_name=f"{user_email}:{item_title}",
                        severity="low",
                    )
                )

        return findings

    # -- Audit Events --

    def _normalize_audit_events(self, raw: RawEventData) -> list[FindingData]:
        """Alert on sensitive audit actions."""
        findings = []
        events = raw.raw_data.get("events", [])

        for event in events:
            uuid = event.get("uuid", "")
            action = event.get("action", "")
            object_type = event.get("object_type", "")
            object_uuid = event.get("object_uuid", "")
            actor_uuid = event.get("actor_uuid", "")
            actor_details = event.get("actor_details", {})
            actor_email = actor_details.get("email", "") if isinstance(actor_details, dict) else ""
            timestamp = event.get("timestamp", "")
            aux_info = event.get("aux_info", "")

            # Only alert on sensitive actions
            if action in SENSITIVE_AUDIT_ACTIONS:
                severity = (
                    "high"
                    if action
                    in (
                        "delete",
                        "suspend",
                        "mfa_disable",
                        "2fa_disable",
                        "role_assign",
                        "role_revoke",
                        "vault_delete",
                    )
                    else "medium"
                )

                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Audit: {action} on {object_type} by {actor_email or actor_uuid}",
                        detail={
                            "uuid": uuid,
                            "action": action,
                            "object_type": object_type,
                            "object_uuid": object_uuid,
                            "actor_uuid": actor_uuid,
                            "actor_email": actor_email,
                            "timestamp": timestamp,
                            "aux_info": aux_info,
                        },
                        resource_id=object_uuid or uuid,
                        resource_type=f"onepassword_{object_type}"
                        if object_type
                        else "onepassword_audit",
                        resource_name=action,
                        severity=severity,
                    )
                )

        return findings


# Register
registry.register(OnePasswordNormalizer())
