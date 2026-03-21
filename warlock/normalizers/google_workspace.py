"""Google Workspace normalizer — transforms raw Admin SDK responses into Findings.

Handles users, org units, admin activity, and login audit.
Flags: users without MFA, suspended users, super admin changes,
suspicious logins (failed, from unusual locations).
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class GoogleWorkspaceNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "gws_users": "_normalize_users",
        "gws_org_units": "_normalize_org_units",
        "gws_admin_activity": "_normalize_admin_activity",
        "gws_login_audit": "_normalize_login_audit",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "google_workspace" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Google Workspace findings."""
        return {
            "raw_event_id": raw.id,
            "source": "google_workspace",
            "source_type": SourceType.COLLABORATION,
            "provider": "google",
            "observed_at": raw.observed_at,
        }

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        """Inventory users; flag users without MFA and suspended users."""
        findings = []
        users = raw.raw_data.get("users", [])

        for user in users:
            user_id = user.get("id", "")
            email = user.get("primaryEmail", "")
            full_name = user.get("name", {}).get("fullName", "") if isinstance(user.get("name"), dict) else ""
            is_admin = user.get("isAdmin", False)
            is_delegated_admin = user.get("isDelegatedAdmin", False)
            is_suspended = user.get("suspended", False)
            is_archived = user.get("archived", False)
            is_enrolled_in_2sv = user.get("isEnrolledIn2Sv", False)
            is_enforced_in_2sv = user.get("isEnforcedIn2Sv", False)
            creation_time = user.get("creationTime", "")
            last_login_time = user.get("lastLoginTime", "")
            org_unit_path = user.get("orgUnitPath", "")

            # Inventory
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Google Workspace user: {full_name} ({email})",
                    detail={
                        "user_id": user_id,
                        "email": email,
                        "full_name": full_name,
                        "is_admin": is_admin,
                        "is_delegated_admin": is_delegated_admin,
                        "is_suspended": is_suspended,
                        "is_enrolled_in_2sv": is_enrolled_in_2sv,
                        "is_enforced_in_2sv": is_enforced_in_2sv,
                        "org_unit_path": org_unit_path,
                        "creation_time": creation_time,
                        "last_login_time": last_login_time,
                    },
                    resource_id=user_id,
                    resource_type="gws_user",
                    resource_name=full_name or email,
                    severity="info",
                )
            )

            # Flag active users without MFA enrolled
            if not is_enrolled_in_2sv and not is_suspended and not is_archived:
                severity = "critical" if is_admin else "high"
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="misconfiguration",
                        title=f"User without MFA: {full_name or email}",
                        detail={
                            "user_id": user_id,
                            "email": email,
                            "is_admin": is_admin,
                            "is_enrolled_in_2sv": False,
                            "is_enforced_in_2sv": is_enforced_in_2sv,
                            "issue": f"{'Admin user' if is_admin else 'User'} has not enrolled in 2-step verification — account is unprotected by second factor",
                        },
                        resource_id=user_id,
                        resource_type="gws_user",
                        resource_name=full_name or email,
                        severity=severity,
                    )
                )

            # Flag suspended users (informational but important for compliance)
            if is_suspended:
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Suspended user: {full_name or email}",
                        detail={
                            "user_id": user_id,
                            "email": email,
                            "is_suspended": True,
                            "last_login_time": last_login_time,
                            "issue": "User account is suspended — verify this is intentional and access has been properly revoked",
                        },
                        resource_id=user_id,
                        resource_type="gws_user",
                        resource_name=full_name or email,
                        severity="low",
                    )
                )

        return findings

    # -- Org Units --

    def _normalize_org_units(self, raw: RawEventData) -> list[FindingData]:
        """Inventory organizational units."""
        findings = []
        org_units = raw.raw_data.get("org_units", [])

        for ou in org_units:
            ou_id = ou.get("orgUnitId", "")
            ou_name = ou.get("name", "")
            ou_path = ou.get("orgUnitPath", "")
            parent_path = ou.get("parentOrgUnitPath", "")
            description = ou.get("description", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Google Workspace OU: {ou_name} ({ou_path})",
                    detail={
                        "org_unit_id": ou_id,
                        "name": ou_name,
                        "org_unit_path": ou_path,
                        "parent_org_unit_path": parent_path,
                        "description": description,
                    },
                    resource_id=ou_id,
                    resource_type="gws_org_unit",
                    resource_name=ou_name,
                    severity="info",
                )
            )

        return findings

    # -- Admin Activity --

    def _normalize_admin_activity(self, raw: RawEventData) -> list[FindingData]:
        """Inventory admin activity; flag super admin privilege changes."""
        findings = []
        activities = raw.raw_data.get("activities", [])

        for activity in activities:
            activity_id = activity.get("id", {})
            unique_qualifier = activity_id.get("uniqueQualifier", "") if isinstance(activity_id, dict) else ""
            actor = activity.get("actor", {}) if isinstance(activity.get("actor"), dict) else {}
            actor_email = actor.get("email", "")
            events = activity.get("events", [])
            time = activity.get("id", {}).get("time", "") if isinstance(activity.get("id"), dict) else ""
            ip_address = activity.get("ipAddress", "")

            for event in events:
                event_type = event.get("type", "")
                event_name = event.get("name", "")
                parameters = event.get("parameters", [])

                # Inventory
                findings.append(
                    FindingData(
                        **self._base(raw),
                        observation_type="inventory",
                        title=f"Admin activity: {event_name} by {actor_email}",
                        detail={
                            "unique_qualifier": unique_qualifier,
                            "actor_email": actor_email,
                            "event_type": event_type,
                            "event_name": event_name,
                            "ip_address": ip_address,
                            "time": time,
                            "parameter_count": len(parameters),
                        },
                        resource_id=unique_qualifier,
                        resource_type="gws_admin_event",
                        resource_name=f"{event_name}:{actor_email}",
                        severity="info",
                    )
                )

                # Flag super admin privilege changes
                admin_change_events = (
                    "ASSIGN_ROLE",
                    "UNASSIGN_ROLE",
                    "GRANT_ADMIN_PRIVILEGE",
                    "REVOKE_ADMIN_PRIVILEGE",
                    "ADD_PRIVILEGE",
                    "UPDATE_ROLE",
                )
                if event_name in admin_change_events:
                    # Extract target user from parameters
                    target_user = ""
                    role_name = ""
                    for param in parameters:
                        if param.get("name") == "USER_EMAIL":
                            target_user = param.get("value", "")
                        if param.get("name") == "ROLE_NAME":
                            role_name = param.get("value", "")

                    is_super_admin = "super" in role_name.lower() if role_name else False
                    severity = "critical" if is_super_admin else "high"

                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Admin privilege change: {event_name} for {target_user or 'unknown'}",
                            detail={
                                "actor_email": actor_email,
                                "event_name": event_name,
                                "target_user": target_user,
                                "role_name": role_name,
                                "ip_address": ip_address,
                                "issue": f"Admin privilege change ({event_name}) performed by {actor_email} — verify this was authorized",
                            },
                            resource_id=unique_qualifier,
                            resource_type="gws_admin_event",
                            resource_name=f"{event_name}:{target_user or actor_email}",
                            severity=severity,
                        )
                    )

        return findings

    # -- Login Audit --

    def _normalize_login_audit(self, raw: RawEventData) -> list[FindingData]:
        """Flag suspicious login events (failures, unusual patterns)."""
        findings = []
        activities = raw.raw_data.get("activities", [])

        for activity in activities:
            activity_id = activity.get("id", {})
            unique_qualifier = activity_id.get("uniqueQualifier", "") if isinstance(activity_id, dict) else ""
            actor = activity.get("actor", {}) if isinstance(activity.get("actor"), dict) else {}
            actor_email = actor.get("email", "")
            ip_address = activity.get("ipAddress", "")
            events = activity.get("events", [])
            time = activity.get("id", {}).get("time", "") if isinstance(activity.get("id"), dict) else ""

            for event in events:
                event_name = event.get("name", "")
                event_type = event.get("type", "")
                parameters = event.get("parameters", [])

                # Extract login details
                login_type = ""
                is_suspicious = False
                for param in parameters:
                    if param.get("name") == "login_type":
                        login_type = param.get("value", "")
                    if param.get("name") == "is_suspicious":
                        is_suspicious = param.get("boolValue", False)

                # Flag failed logins
                if event_name == "login_failure":
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Login failure: {actor_email}",
                            detail={
                                "actor_email": actor_email,
                                "event_name": event_name,
                                "ip_address": ip_address,
                                "login_type": login_type,
                                "time": time,
                                "issue": f"Failed login attempt for {actor_email} from {ip_address}",
                            },
                            resource_id=unique_qualifier,
                            resource_type="gws_login_event",
                            resource_name=f"login_failure:{actor_email}",
                            severity="medium",
                        )
                    )

                # Flag suspicious logins
                if is_suspicious or event_name == "suspicious_login":
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Suspicious login detected: {actor_email}",
                            detail={
                                "actor_email": actor_email,
                                "event_name": event_name,
                                "ip_address": ip_address,
                                "login_type": login_type,
                                "is_suspicious": True,
                                "time": time,
                                "issue": f"Suspicious login detected for {actor_email} from {ip_address} — potential account compromise",
                            },
                            resource_id=unique_qualifier,
                            resource_type="gws_login_event",
                            resource_name=f"suspicious:{actor_email}",
                            severity="high",
                        )
                    )

                # Flag login challenge events (password leak, gov-backed attack)
                if event_name in ("gov_attack_warning", "login_challenge"):
                    findings.append(
                        FindingData(
                            **self._base(raw),
                            observation_type="alert",
                            title=f"Login security event: {event_name} for {actor_email}",
                            detail={
                                "actor_email": actor_email,
                                "event_name": event_name,
                                "event_type": event_type,
                                "ip_address": ip_address,
                                "time": time,
                                "issue": f"Security event ({event_name}) for {actor_email} — immediate investigation required",
                            },
                            resource_id=unique_qualifier,
                            resource_type="gws_login_event",
                            resource_name=f"{event_name}:{actor_email}",
                            severity="critical",
                        )
                    )

        return findings


# Register
registry.register(GoogleWorkspaceNormalizer())
