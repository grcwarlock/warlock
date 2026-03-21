"""Bitwarden normalizer — transforms raw Bitwarden Public API responses into Findings.

Handles organization members, policies, and event logs.
Flags: members without 2FA, weak master password policy, revoked/inactive members
still in org, sensitive collection access.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# Bitwarden member status codes
MEMBER_STATUS = {
    0: "invited",
    1: "accepted",
    2: "confirmed",
    -1: "revoked",
}

# Bitwarden member type codes
MEMBER_TYPE = {
    0: "owner",
    1: "admin",
    2: "user",
    3: "manager",
    4: "custom",
}

# Bitwarden policy type codes
POLICY_TYPE = {
    0: "two_factor_authentication",
    1: "master_password",
    2: "password_generator",
    3: "only_org",
    4: "require_sso",
    5: "personal_ownership",
    6: "disable_send",
    7: "send_options",
    8: "reset_password",
    9: "maximum_vault_timeout",
    10: "disable_personal_vault_export",
}

# Sensitive event types to alert on
SENSITIVE_EVENT_TYPES = {
    1000,  # User logged in
    1001,  # User changed password
    1002,  # User enabled/updated 2FA
    1003,  # User disabled 2FA
    1004,  # User recovered 2FA
    1006,  # User failed login
    1007,  # User failed 2FA
    1500,  # Organization member invited
    1501,  # Organization member confirmed
    1502,  # Organization member updated
    1503,  # Organization member removed
    1504,  # Organization member groups changed
    1600,  # Organization policy updated
    1700,  # Organization export
}


class BitwardenNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "bitwarden_members": "_normalize_members",
        "bitwarden_policies": "_normalize_policies",
        "bitwarden_events": "_normalize_events",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "bitwarden" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Bitwarden findings."""
        return {
            "raw_event_id": raw.id,
            "source": "bitwarden",
            "source_type": SourceType.IAM,
            "provider": "bitwarden",
            "observed_at": raw.observed_at,
        }

    # -- Members --

    def _normalize_members(self, raw: RawEventData) -> list[FindingData]:
        """Inventory members; flag missing 2FA and revoked/inactive members."""
        findings = []
        members = raw.raw_data.get("members", [])

        for member in members:
            member_id = member.get("id", "")
            user_id = member.get("userId", "")
            email = member.get("email", "")
            name = member.get("name", "")
            status_code = member.get("status", 0)
            type_code = member.get("type", 2)
            two_factor_enabled = member.get("twoFactorEnabled", False)
            external_id = member.get("externalId", "")
            collections = member.get("collections", [])

            status = MEMBER_STATUS.get(status_code, str(status_code))
            member_type = MEMBER_TYPE.get(type_code, str(type_code))

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Bitwarden member: {email} ({member_type}, {status})",
                    detail={
                        "member_id": member_id,
                        "user_id": user_id,
                        "email": email,
                        "name": name,
                        "status": status,
                        "type": member_type,
                        "two_factor_enabled": two_factor_enabled,
                        "external_id": external_id,
                        "collection_count": len(collections),
                    },
                    resource_id=member_id,
                    resource_type="bitwarden_member",
                    resource_name=email or name,
                    severity="info",
                )
            )

            # Flag members without 2FA (only for confirmed/accepted members)
            if not two_factor_enabled and status in ("confirmed", "accepted"):
                severity = "critical" if member_type in ("owner", "admin") else "high"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Member without 2FA: {email} ({member_type})",
                        detail={
                            "member_id": member_id,
                            "email": email,
                            "type": member_type,
                            "status": status,
                            "two_factor_enabled": False,
                            "issue": f"{member_type.title()} user has no two-factor authentication — vault access relies solely on master password",
                        },
                        resource_id=member_id,
                        resource_type="bitwarden_member",
                        resource_name=email or name,
                        severity=severity,
                    )
                )

            # Flag revoked members still in org
            if status == "revoked":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="policy_violation",
                        title=f"Revoked member still in organization: {email}",
                        detail={
                            "member_id": member_id,
                            "email": email,
                            "status": "revoked",
                            "type": member_type,
                            "issue": "Revoked user remains in the organization — should be fully removed during offboarding",
                        },
                        resource_id=member_id,
                        resource_type="bitwarden_member",
                        resource_name=email or name,
                        severity="medium",
                    )
                )

            # Flag invited members (stale invitations)
            if status == "invited":
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Pending invitation: {email}",
                        detail={
                            "member_id": member_id,
                            "email": email,
                            "status": "invited",
                            "type": member_type,
                            "issue": "Member invitation is pending — verify legitimacy and follow up or revoke",
                        },
                        resource_id=member_id,
                        resource_type="bitwarden_member",
                        resource_name=email or name,
                        severity="low",
                    )
                )

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        """Inventory policies; flag weak or disabled security policies."""
        findings = []
        policies = raw.raw_data.get("policies", [])

        two_fa_enforced = False
        master_pw_policy_enabled = False

        for policy in policies:
            policy_id = policy.get("id", "")
            type_code = policy.get("type", -1)
            enabled = policy.get("enabled", False)
            policy_data = policy.get("data", {})
            policy_type = POLICY_TYPE.get(type_code, str(type_code))

            # Track key policies
            if type_code == 0:
                two_fa_enforced = enabled
            if type_code == 1:
                master_pw_policy_enabled = enabled

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Bitwarden policy: {policy_type} ({'enabled' if enabled else 'disabled'})",
                    detail={
                        "policy_id": policy_id,
                        "type": policy_type,
                        "type_code": type_code,
                        "enabled": enabled,
                        "data": policy_data,
                    },
                    resource_id=policy_id,
                    resource_type="bitwarden_policy",
                    resource_name=policy_type,
                    severity="info",
                )
            )

        # Flag if 2FA policy is not enforced
        if not two_fa_enforced:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="Two-factor authentication policy not enforced",
                    detail={
                        "policy_type": "two_factor_authentication",
                        "enabled": False,
                        "issue": "Organization does not enforce 2FA — members can access vaults without a second factor",
                    },
                    resource_id="policy:2fa",
                    resource_type="bitwarden_policy",
                    resource_name="two_factor_authentication",
                    severity="high",
                )
            )

        # Flag if master password policy is not enabled
        if not master_pw_policy_enabled:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="Master password policy not enforced",
                    detail={
                        "policy_type": "master_password",
                        "enabled": False,
                        "issue": "No master password complexity requirements — members may use weak passwords",
                    },
                    resource_id="policy:master_password",
                    resource_type="bitwarden_policy",
                    resource_name="master_password",
                    severity="medium",
                )
            )

        return findings

    # -- Events --

    def _normalize_events(self, raw: RawEventData) -> list[FindingData]:
        """Alert on sensitive event types."""
        findings = []
        events = raw.raw_data.get("events", [])

        for event in events:
            event_id = event.get("id", "")
            event_type_code = event.get("type", 0)
            acting_user_id = event.get("actingUserId", "")
            member_id = event.get("memberId", "")
            collection_id = event.get("collectionId", "")
            date = event.get("date", "")
            device = event.get("device", "")
            ip_address = event.get("ipAddress", "")

            if event_type_code not in SENSITIVE_EVENT_TYPES:
                continue

            # Determine severity based on event type
            if event_type_code in (1003, 1007, 1503, 1700):
                severity = "high"
            elif event_type_code in (1006, 1502, 1504, 1600):
                severity = "medium"
            else:
                severity = "low"

            # Map event type code to a readable name
            event_names = {
                1000: "user_login",
                1001: "password_changed",
                1002: "2fa_enabled",
                1003: "2fa_disabled",
                1004: "2fa_recovered",
                1006: "login_failed",
                1007: "2fa_failed",
                1500: "member_invited",
                1501: "member_confirmed",
                1502: "member_updated",
                1503: "member_removed",
                1504: "member_groups_changed",
                1600: "policy_updated",
                1700: "organization_export",
            }
            event_name = event_names.get(event_type_code, f"event_{event_type_code}")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Bitwarden event: {event_name} by {acting_user_id or 'system'}",
                    detail={
                        "event_id": event_id,
                        "event_type": event_type_code,
                        "event_name": event_name,
                        "acting_user_id": acting_user_id,
                        "member_id": member_id,
                        "collection_id": collection_id,
                        "date": date,
                        "device": device,
                        "ip_address": ip_address,
                    },
                    resource_id=event_id,
                    resource_type="bitwarden_event",
                    resource_name=event_name,
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(BitwardenNormalizer())
