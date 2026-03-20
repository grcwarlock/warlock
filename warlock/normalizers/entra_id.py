"""Entra ID normalizer — transforms raw MS Graph API responses into Findings.

Normalizes risky sign-ins, users without MFA, stale accounts,
and overprivileged service principals.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class EntraIDNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "entra_users": "_normalize_users",
        "entra_risky_users": "_normalize_risky_users",
        "entra_sign_ins": "_normalize_sign_ins",
        "entra_directory_audits": "_normalize_directory_audits",
        "entra_conditional_access_policies": "_normalize_conditional_access",
        "entra_service_principals": "_normalize_service_principals",
        "entra_app_registrations": "_normalize_app_registrations",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "entra_id" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Entra ID findings."""
        return {
            "raw_event_id": raw.id,
            "source": "entra_id",
            "source_type": SourceType.IAM,
            "provider": "entra_id",
            "account_id": raw.raw_data.get("tenant_id", ""),
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
            upn = user.get("userPrincipalName", "unknown")
            enabled = user.get("accountEnabled", True)
            sign_in_activity = user.get("signInActivity", {})
            last_sign_in = sign_in_activity.get("lastSignInDateTime") if sign_in_activity else None

            issues = []
            if not enabled:
                issues.append("account_disabled")

            if last_sign_in:
                try:
                    last_dt = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
                    if last_dt < stale_threshold:
                        issues.append("stale_account_90_days")
                except (ValueError, TypeError):
                    pass
            elif enabled:
                issues.append("never_signed_in")

            severity = "info"
            obs_type = "inventory"
            if "stale_account_90_days" in issues:
                severity = "medium"
                obs_type = "policy_violation"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Entra user: {upn}" + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "user_id": user.get("id", ""),
                        "upn": upn,
                        "account_enabled": enabled,
                        "last_sign_in": last_sign_in,
                        "issues": issues,
                    },
                    resource_id=user.get("id", ""),
                    resource_type="entra_user",
                    resource_name=upn,
                    severity=severity,
                )
            )

        return findings

    # -- Risky Users --

    def _normalize_risky_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        risky_users = raw.raw_data.get("response", [])

        for user in risky_users:
            risk_level = user.get("riskLevel", "none")
            risk_state = user.get("riskState", "none")
            upn = user.get("userPrincipalName", "unknown")

            severity_map = {"high": "critical", "medium": "high", "low": "medium"}
            severity = severity_map.get(risk_level, "info")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert" if risk_level != "none" else "inventory",
                    title=f"Risky user: {upn} — risk level {risk_level}",
                    detail={
                        "user_id": user.get("id", ""),
                        "upn": upn,
                        "risk_level": risk_level,
                        "risk_state": risk_state,
                        "risk_detail": user.get("riskDetail", ""),
                        "risk_last_updated": user.get("riskLastUpdatedDateTime", ""),
                    },
                    resource_id=user.get("id", ""),
                    resource_type="entra_user",
                    resource_name=upn,
                    severity=severity,
                )
            )

        return findings

    # -- Sign-Ins (failed) --

    def _normalize_sign_ins(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        sign_ins = raw.raw_data.get("response", [])

        for event in sign_ins:
            upn = event.get("userPrincipalName", "unknown")
            error_code = event.get("status", {}).get("errorCode", 0)
            failure_reason = event.get("status", {}).get("failureReason", "")
            risk_level = event.get("riskLevelDuringSignIn", "none")
            conditional_access = event.get("conditionalAccessStatus", "notApplied")

            issues = []
            if error_code != 0:
                issues.append("failed_sign_in")
            if risk_level in ("high", "medium"):
                issues.append(f"risky_sign_in_{risk_level}")
            if conditional_access == "failure":
                issues.append("conditional_access_blocked")

            severity = "info"
            if risk_level == "high":
                severity = "high"
            elif risk_level == "medium":
                severity = "medium"
            elif error_code != 0:
                severity = "low"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert" if issues else "inventory",
                    title=f"Sign-in event: {upn} — {failure_reason}"
                    if failure_reason
                    else f"Sign-in event: {upn}",
                    detail={
                        "user_id": event.get("userId", ""),
                        "upn": upn,
                        "error_code": error_code,
                        "failure_reason": failure_reason,
                        "risk_level": risk_level,
                        "conditional_access_status": conditional_access,
                        "ip_address": event.get("ipAddress", ""),
                        "location": event.get("location", {}),
                        "issues": issues,
                    },
                    resource_id=event.get("userId", ""),
                    resource_type="entra_sign_in",
                    resource_name=upn,
                    severity=severity,
                )
            )

        return findings

    # -- Directory Audits --

    def _normalize_directory_audits(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        audits = raw.raw_data.get("response", [])

        privilege_activities = {
            "Add member to role",
            "Add eligible member to role",
            "Add owner to service principal",
            "Add app role assignment to service principal",
        }

        for audit in audits:
            activity = audit.get("activityDisplayName", "")
            actor = audit.get("initiatedBy", {})
            actor_upn = actor.get("user", {}).get("userPrincipalName", "system")

            issues = []
            severity = "info"
            obs_type = "inventory"

            if activity in privilege_activities:
                issues.append("privilege_change")
                severity = "high"
                obs_type = "access_anomaly"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Audit: {activity} by {actor_upn}",
                    detail={
                        "activity": activity,
                        "actor": actor_upn,
                        "result": audit.get("result", ""),
                        "target_resources": audit.get("targetResources", []),
                        "issues": issues,
                    },
                    resource_id=audit.get("id", ""),
                    resource_type="entra_audit",
                    resource_name=activity,
                    severity=severity,
                )
            )

        return findings

    # -- Conditional Access Policies --

    def _normalize_conditional_access(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        policies = raw.raw_data.get("response", [])

        for policy in policies:
            name = policy.get("displayName", "unknown")
            state = policy.get("state", "disabled")

            issues = []
            if state == "disabled":
                issues.append("policy_disabled")
            elif state == "enabledForReportingButNotEnforced":
                issues.append("policy_report_only")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "low"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Conditional access: {name}"
                    + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "policy_id": policy.get("id", ""),
                        "name": name,
                        "state": state,
                        "conditions": policy.get("conditions", {}),
                        "grant_controls": policy.get("grantControls", {}),
                        "issues": issues,
                    },
                    resource_id=policy.get("id", ""),
                    resource_type="entra_conditional_access_policy",
                    resource_name=name,
                    severity=severity,
                )
            )

        return findings

    # -- Service Principals --

    def _normalize_service_principals(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        sps = raw.raw_data.get("response", [])

        high_privilege_permissions = {
            "Directory.ReadWrite.All",
            "Application.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "User.ReadWrite.All",
        }

        for sp in sps:
            name = sp.get("displayName", "unknown")
            app_roles = sp.get("appRoles", [])
            oauth2_permissions = sp.get("oauth2PermissionScopes", [])

            issues = []
            granted_permissions = set()
            for role in app_roles:
                if role.get("isEnabled", False):
                    granted_permissions.add(role.get("value", ""))
            for perm in oauth2_permissions:
                granted_permissions.add(perm.get("value", ""))

            overprivileged = granted_permissions & high_privilege_permissions
            if overprivileged:
                issues.append(f"high_privilege_permissions: {', '.join(overprivileged)}")

            if not sp.get("accountEnabled", True):
                issues.append("disabled")

            severity = "info"
            obs_type = "inventory"
            if overprivileged:
                severity = "high"
                obs_type = "access_anomaly"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Service principal: {name}"
                    + (" — overprivileged" if overprivileged else ""),
                    detail={
                        "sp_id": sp.get("id", ""),
                        "app_id": sp.get("appId", ""),
                        "name": name,
                        "enabled": sp.get("accountEnabled", True),
                        "granted_permissions": list(granted_permissions),
                        "issues": issues,
                    },
                    resource_id=sp.get("id", ""),
                    resource_type="entra_service_principal",
                    resource_name=name,
                    severity=severity,
                )
            )

        return findings

    # -- App Registrations --

    def _normalize_app_registrations(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        apps = raw.raw_data.get("response", [])

        for app in apps:
            name = app.get("displayName", "unknown")
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"App registration: {name}",
                    detail=app,
                    resource_id=app.get("id", ""),
                    resource_type="entra_app_registration",
                    resource_name=name,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(EntraIDNormalizer())
