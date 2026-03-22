"""Slack normalizer — transforms raw Slack API responses into Findings.

Handles workspace info, DLP events, audit logs, and users.
Flags: users without SSO, external file shares, admin role changes,
workspace without 2FA requirement.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SlackNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "slack_workspace": "_normalize_workspace",
        "slack_dlp_events": "_normalize_dlp_events",
        "slack_audit_logs": "_normalize_audit_logs",
        "slack_users": "_normalize_users",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "slack" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Slack findings."""
        return {
            "raw_event_id": raw.id,
            "source": "slack",
            "source_type": SourceType.COLLABORATION,
            "provider": "slack",
            "observed_at": raw.observed_at,
        }

    # -- Workspace --

    def _normalize_workspace(self, raw: RawEventData) -> list[FindingData]:
        """Inventory workspace; flag missing 2FA requirement."""
        findings = []
        team = raw.raw_data.get("team", {})

        team_id = team.get("id", "")
        team_name = team.get("name", "")
        domain = team.get("domain", "")
        icon = team.get("icon", {})
        enterprise_id = team.get("enterprise_id", "")

        # Inventory
        findings.append(
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Slack workspace: {team_name} ({domain})",
                detail={
                    "team_id": team_id,
                    "team_name": team_name,
                    "domain": domain,
                    "enterprise_id": enterprise_id,
                    "has_icon": bool(icon),
                },
                resource_id=team_id,
                resource_type="slack_workspace",
                resource_name=team_name,
                severity="info",
            )
        )

        # Check for 2FA requirement (available in team.prefs or via admin.teams.settings)
        # The team.info response may not include this directly, but we check common fields
        prefs = team.get("prefs", {}) if isinstance(team.get("prefs"), dict) else {}
        require_2fa = prefs.get("require_2fa", None)

        if require_2fa is False:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title=f"Workspace 2FA not required: {team_name}",
                    detail={
                        "team_id": team_id,
                        "team_name": team_name,
                        "require_2fa": False,
                        "issue": "Workspace does not require two-factor authentication — accounts are protected by password only",
                    },
                    resource_id=team_id,
                    resource_type="slack_workspace",
                    resource_name=team_name,
                    severity="high",
                )
            )

        return findings

    # -- DLP Events --

    def _normalize_dlp_events(self, raw: RawEventData) -> list[FindingData]:
        """Flag externally shared files."""
        findings = []
        files = raw.raw_data.get("files", [])

        for file in files:
            file_id = file.get("id", "")
            file_name = file.get("name", "")
            file_type = file.get("filetype", "")
            user = file.get("user", "")
            is_external = file.get("is_external", False)
            is_public = file.get("is_public", False)
            shared_with = file.get("channels", [])
            created = file.get("created", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"External file share detected: {file_name}",
                    detail={
                        "file_id": file_id,
                        "file_name": file_name,
                        "file_type": file_type,
                        "user": user,
                        "is_external": is_external,
                        "is_public": is_public,
                        "shared_channels": shared_with,
                        "created": created,
                        "issue": "File is shared externally or publicly — potential data leakage",
                    },
                    resource_id=file_id,
                    resource_type="slack_file",
                    resource_name=file_name,
                    severity="medium",
                )
            )

        return findings

    # -- Audit Logs --

    def _normalize_audit_logs(self, raw: RawEventData) -> list[FindingData]:
        """Inventory audit events; flag admin role changes."""
        findings = []
        entries = raw.raw_data.get("entries", [])

        for entry in entries:
            entry_id = entry.get("id", "")
            action = entry.get("action", "")
            actor = entry.get("actor", {}) if isinstance(entry.get("actor"), dict) else {}
            actor_email = (
                actor.get("user", {}).get("email", "")
                if isinstance(actor.get("user"), dict)
                else ""
            )
            actor_name = (
                actor.get("user", {}).get("name", "") if isinstance(actor.get("user"), dict) else ""
            )
            entity = entry.get("entity", {}) if isinstance(entry.get("entity"), dict) else {}
            entity_type = entity.get("type", "")
            date_create = entry.get("date_create", "")
            context = entry.get("context", {}) if isinstance(entry.get("context"), dict) else {}

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Slack audit: {action} by {actor_name or actor_email}",
                    detail={
                        "entry_id": entry_id,
                        "action": action,
                        "actor_email": actor_email,
                        "actor_name": actor_name,
                        "entity_type": entity_type,
                        "date_create": date_create,
                    },
                    resource_id=entry_id,
                    resource_type="slack_audit_event",
                    resource_name=f"{action}:{actor_name or actor_email}",
                    severity="info",
                )
            )

            # Flag admin role changes
            admin_actions = (
                "role_change_to_admin",
                "role_change_to_owner",
                "owner_transferred",
                "role_change_to_primary_owner",
            )
            if action in admin_actions:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="alert",
                        title=f"Admin role change: {action} by {actor_name or actor_email}",
                        detail={
                            "entry_id": entry_id,
                            "action": action,
                            "actor_email": actor_email,
                            "actor_name": actor_name,
                            "entity": entity,
                            "context": context,
                            "issue": f"Privileged role change detected ({action}) — verify this was authorized",
                        },
                        resource_id=entry_id,
                        resource_type="slack_audit_event",
                        resource_name=f"{action}:{actor_name or actor_email}",
                        severity="high",
                    )
                )

        return findings

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """Inventory users; flag users without SSO."""
        findings = []
        users = raw.raw_data.get("users", [])

        for user in users:
            user_id = user.get("id", "")
            name = user.get("name", "")
            real_name = user.get("real_name", user.get("profile", {}).get("real_name", ""))
            email = (
                user.get("profile", {}).get("email", "")
                if isinstance(user.get("profile"), dict)
                else ""
            )
            is_admin = user.get("is_admin", False)
            is_owner = user.get("is_owner", False)
            is_bot = user.get("is_bot", False)
            deleted = user.get("deleted", False)
            has_2fa = user.get("has_2fa", False)
            is_restricted = user.get("is_restricted", False)
            is_ultra_restricted = user.get("is_ultra_restricted", False)
            enterprise_user = (
                user.get("enterprise_user", {})
                if isinstance(user.get("enterprise_user"), dict)
                else {}
            )
            is_sso = bool(enterprise_user) or user.get("is_app_user", False)

            # Skip bots and deleted users for inventory
            if is_bot or deleted:
                continue

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Slack user: {real_name or name} ({email})",
                    detail={
                        "user_id": user_id,
                        "name": name,
                        "real_name": real_name,
                        "email": email,
                        "is_admin": is_admin,
                        "is_owner": is_owner,
                        "has_2fa": has_2fa,
                        "is_restricted": is_restricted,
                        "is_sso": is_sso,
                    },
                    resource_id=user_id,
                    resource_type="slack_user",
                    resource_name=real_name or name,
                    severity="info",
                )
            )

            # Flag users without SSO (non-restricted, non-guest users)
            if not is_sso and not is_restricted and not is_ultra_restricted:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"User without SSO: {real_name or name}",
                        detail={
                            "user_id": user_id,
                            "name": name,
                            "email": email,
                            "is_sso": False,
                            "has_2fa": has_2fa,
                            "issue": "User authenticates without SSO — identity is not federated through corporate identity provider",
                        },
                        resource_id=user_id,
                        resource_type="slack_user",
                        resource_name=real_name or name,
                        severity="medium",
                    )
                )

            # Flag admins/owners without 2FA
            if (is_admin or is_owner) and not has_2fa:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"Admin without 2FA: {real_name or name}",
                        detail={
                            "user_id": user_id,
                            "name": name,
                            "email": email,
                            "is_admin": is_admin,
                            "is_owner": is_owner,
                            "has_2fa": False,
                            "issue": "Admin/owner account does not have 2FA enabled — privileged account is protected by password only",
                        },
                        resource_id=user_id,
                        resource_type="slack_user",
                        resource_name=real_name or name,
                        severity="critical",
                    )
                )

        return findings


# Register
registry.register(SlackNormalizer())
