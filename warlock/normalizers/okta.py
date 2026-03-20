"""Okta normalizer — transforms raw Okta API responses into Findings.

Normalizes users (MFA status, last login, suspended accounts),
system log events (failed logins, MFA bypass, admin privilege grants),
and policies (password policy strength).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class OktaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "okta_users": "_normalize_users",
        "okta_groups": "_normalize_groups",
        "okta_system_log": "_normalize_system_log",
        "okta_policies": "_normalize_policies",
        "okta_applications": "_normalize_applications",
        "okta_factors": "_normalize_factors",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "okta" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Okta findings."""
        return {
            "raw_event_id": raw.id,
            "source": "okta",
            "source_type": SourceType.IAM,
            "provider": "okta",
            "account_id": raw.raw_data.get("domain", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Users --

    def _normalize_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        users = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=90)

        for user in users:
            profile = user.get("profile", {})
            status = user.get("status", "UNKNOWN")
            login = profile.get("login", "unknown")
            last_login_str = user.get("lastLogin")

            issues = []
            if status == "SUSPENDED":
                issues.append("account_suspended")
            if status == "DEPROVISIONED":
                issues.append("account_deprovisioned")

            if last_login_str:
                try:
                    last_login = datetime.fromisoformat(last_login_str.replace("Z", "+00:00"))
                    if last_login < stale_threshold:
                        issues.append("stale_account_90_days")
                except (ValueError, TypeError):
                    pass
            elif status == "ACTIVE":
                issues.append("never_logged_in")

            severity = "info"
            obs_type = "inventory"
            if "stale_account_90_days" in issues:
                severity = "medium"
                obs_type = "policy_violation"
            if "account_suspended" in issues:
                severity = "medium"
                obs_type = "policy_violation"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Okta user: {login}" + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "user_id": user.get("id", ""),
                        "login": login,
                        "status": status,
                        "last_login": last_login_str,
                        "issues": issues,
                    },
                    resource_id=user.get("id", ""),
                    resource_type="okta_user",
                    resource_name=login,
                    severity=severity,
                )
            )

        return findings

    # -- Groups --

    def _normalize_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        groups = raw.raw_data.get("response", [])
        for group in groups:
            profile = group.get("profile", {})
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Okta group: {profile.get('name', '?')}",
                    detail=group,
                    resource_id=group.get("id", ""),
                    resource_type="okta_group",
                    resource_name=profile.get("name", ""),
                    severity="info",
                )
            )
        return findings

    # -- System Log --

    def _normalize_system_log(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        events = raw.raw_data.get("response", [])

        for event in events:
            event_type = event.get("eventType", "")
            outcome = event.get("outcome", {}).get("result", "")
            actor = event.get("actor", {}).get("displayName", "unknown")
            actor_id = event.get("actor", {}).get("id", "")

            severity = "info"
            obs_type = "inventory"
            title = f"Okta event: {event_type}"
            issues = []

            if event_type == "user.session.start" and outcome == "FAILURE":
                severity = "medium"
                obs_type = "alert"
                issues.append("failed_login")
                title = f"Failed login attempt — {actor}"

            elif event_type == "user.authentication.auth_via_mfa" and outcome == "FAILURE":
                severity = "high"
                obs_type = "alert"
                issues.append("mfa_failure")
                title = f"MFA authentication failure — {actor}"

            elif event_type == "user.account.privilege.grant":
                severity = "high"
                obs_type = "access_anomaly"
                issues.append("privilege_grant")
                target = event.get("target", [{}])
                target_name = target[0].get("displayName", "unknown") if target else "unknown"
                title = f"Privilege grant: {actor} → {target_name}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "event_type": event_type,
                        "outcome": outcome,
                        "actor": actor,
                        "actor_id": actor_id,
                        "issues": issues,
                        "event": event,
                    },
                    resource_id=actor_id,
                    resource_type="okta_event",
                    resource_name=actor,
                    severity=severity,
                )
            )

        return findings

    # -- Policies --

    def _normalize_policies(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        policies = raw.raw_data.get("response", [])

        for policy in policies:
            policy_type = policy.get("type", "")
            name = policy.get("name", "unknown")
            issues = []

            if policy_type == "PASSWORD":
                settings = policy.get("settings", {}).get("password", {})
                complexity = settings.get("complexity", {})

                min_length = complexity.get("minLength", 0)
                if min_length < 12:
                    issues.append(f"min_length_{min_length}_under_12")
                if not complexity.get("minUpperCase", 0):
                    issues.append("no_uppercase_required")
                if not complexity.get("minNumber", 0):
                    issues.append("no_number_required")
                if not complexity.get("minSymbol", 0):
                    issues.append("no_symbol_required")

                age = settings.get("age", {})
                if not age.get("maxAgeDays", 0):
                    issues.append("no_password_expiration")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Okta policy: {name}" + (f" — {len(issues)} issues" if issues else ""),
                    detail={
                        "policy_id": policy.get("id", ""),
                        "policy_type": policy_type,
                        "name": name,
                        "issues": issues,
                        "policy": policy,
                    },
                    resource_id=policy.get("id", ""),
                    resource_type="okta_policy",
                    resource_name=name,
                    severity=severity,
                )
            )

        return findings

    # -- Applications --

    def _normalize_applications(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        apps = raw.raw_data.get("response", [])
        for app in apps:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Okta application: {app.get('label', '?')}",
                    detail=app,
                    resource_id=app.get("id", ""),
                    resource_type="okta_application",
                    resource_name=app.get("label", ""),
                    severity="info",
                )
            )
        return findings

    # -- Factors --

    def _normalize_factors(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        factor_records = raw.raw_data.get("response", [])

        for record in factor_records:
            user_id = record.get("user_id", "")
            factors = record.get("factors", [])
            active_factors = [f for f in factors if f.get("status") == "ACTIVE"]

            issues = []
            if not active_factors:
                issues.append("no_active_mfa")

            severity = "info"
            obs_type = "inventory"
            if "no_active_mfa" in issues:
                severity = "high"
                obs_type = "misconfiguration"

            factor_types = [f.get("factorType", "unknown") for f in active_factors]
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"MFA factors for user {user_id}"
                    + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "user_id": user_id,
                        "active_factor_count": len(active_factors),
                        "factor_types": factor_types,
                        "issues": issues,
                    },
                    resource_id=user_id,
                    resource_type="okta_user_factors",
                    resource_name=user_id,
                    severity=severity,
                )
            )

        return findings


# Register
registry.register(OktaNormalizer())
