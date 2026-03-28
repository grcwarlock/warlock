"""IBM RACF normalizer — transforms raw z/OSMF RACF API responses into Findings.

Normalizes mainframe user profiles, group memberships, and access rules.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry

# RACF attributes that indicate elevated privileges
_PRIVILEGED_ATTRS = frozenset({"SPECIAL", "OPERATIONS", "AUDITOR", "ROAUDIT"})


class RACFNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "racf_users": "_normalize_users",
        "racf_groups": "_normalize_groups",
        "racf_dataset_profiles": "_normalize_dataset_profiles",
        "racf_resource_profiles": "_normalize_resource_profiles",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "racf" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        return {
            "raw_event_id": raw.id,
            "source": "racf",
            "source_type": SourceType.IAM,
            "provider": "racf",
            "account_id": "",
            "region": "",
            "observed_at": raw.observed_at,
        }

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for user in items:
            user_id = str(user.get("userId", user.get("user", user.get("id", ""))))
            name = user.get("name", user.get("userName", user_id))
            attrs = set(user.get("attributes", []))
            is_privileged = bool(attrs & _PRIVILEGED_ATTRS)
            revoked = user.get("revoked", False)

            severity = "high" if is_privileged and not revoked else "info"
            obs_type = "access_anomaly" if is_privileged else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"RACF user: {user_id} ({name})",
                    detail={
                        "user_id": user_id,
                        "name": name,
                        "default_group": user.get("dfltgrp", user.get("defaultGroup", "")),
                        "attributes": list(attrs),
                        "is_privileged": is_privileged,
                        "revoked": revoked,
                        "last_logon": user.get("lastLogon", user.get("last_access", "")),
                        "password_interval": user.get("passwordInterval", None),
                        "created": user.get("created", ""),
                    },
                    resource_id=user_id,
                    resource_type="racf_user",
                    resource_name=name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for group in items:
            group_id = str(group.get("groupId", group.get("group", group.get("id", ""))))
            owner = group.get("owner", "")
            member_count = len(group.get("members", []))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"RACF group: {group_id}",
                    detail={
                        "group_id": group_id,
                        "owner": owner,
                        "superior_group": group.get("superiorGroup", group.get("supgroup", "")),
                        "member_count": member_count,
                        "members": group.get("members", [])[:20],
                        "created": group.get("created", ""),
                    },
                    resource_id=group_id,
                    resource_type="racf_group",
                    resource_name=group_id,
                    severity="info",
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_dataset_profiles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for profile in items:
            profile_name = str(profile.get("name", profile.get("dataset", "")))
            uacc = str(profile.get("uacc", profile.get("universalAccess", "NONE"))).upper()

            # Universal access of ALTER or UPDATE is risky
            severity = "high" if uacc in ("ALTER", "UPDATE") else "info"
            obs_type = "misconfiguration" if uacc in ("ALTER", "UPDATE") else "inventory"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"RACF dataset profile: {profile_name}",
                    detail={
                        "profile_name": profile_name,
                        "universal_access": uacc,
                        "owner": profile.get("owner", ""),
                        "audit_flags": profile.get("audit", ""),
                        "warning_mode": profile.get("warning", False),
                        "created": profile.get("created", ""),
                    },
                    resource_id=profile_name,
                    resource_type="racf_dataset_profile",
                    resource_name=profile_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings

    def _normalize_resource_profiles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        items = raw.raw_data.get("response", [])

        for profile in items:
            profile_name = str(profile.get("name", profile.get("profile", "")))
            class_name = str(profile.get("class", profile.get("className", "FACILITY")))
            uacc = str(profile.get("uacc", profile.get("universalAccess", "NONE"))).upper()

            severity = "medium" if uacc not in ("NONE", "READ") else "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"RACF resource: {class_name}/{profile_name}",
                    detail={
                        "profile_name": profile_name,
                        "class_name": class_name,
                        "universal_access": uacc,
                        "owner": profile.get("owner", ""),
                        "audit_flags": profile.get("audit", ""),
                    },
                    resource_id=f"{class_name}/{profile_name}",
                    resource_type="racf_resource_profile",
                    resource_name=profile_name,
                    severity=severity,
                    confidence=1.0,
                )
            )

        return findings


# Register
registry.register(RACFNormalizer())
