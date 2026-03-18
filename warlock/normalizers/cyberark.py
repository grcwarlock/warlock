"""CyberArk normalizer — transforms raw CyberArk API responses into Findings.

Normalizes privileged accounts (rotation compliance, usage patterns),
safes, platforms, and session recordings.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class CyberArkNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "cyberark_accounts": "_normalize_accounts",
        "cyberark_safes": "_normalize_safes",
        "cyberark_platforms": "_normalize_platforms",
        "cyberark_recordings": "_normalize_recordings",
        "cyberark_password_compliance": "_normalize_password_compliance",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "cyberark" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all CyberArk findings."""
        return {
            "raw_event_id": raw.id,
            "source": "cyberark",
            "source_type": SourceType.IAM,
            "provider": "cyberark",
            "account_id": raw.raw_data.get("base_url", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Accounts --

    def _normalize_accounts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        accounts = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)
        rotation_threshold = now - timedelta(days=90)

        for account in accounts:
            name = account.get("name", "unknown")
            platform_id = account.get("platformId", "")
            safe_name = account.get("safeName", "")
            secret_mgmt = account.get("secretManagement", {})
            last_modified = secret_mgmt.get("lastModifiedTime")
            auto_mgmt = secret_mgmt.get("automaticManagementEnabled", False)

            issues = []

            # Check password rotation compliance
            if last_modified:
                try:
                    # CyberArk returns epoch seconds
                    last_mod_dt = datetime.fromtimestamp(last_modified, tz=timezone.utc)
                    if last_mod_dt < rotation_threshold:
                        issues.append("password_overdue_90_days")
                except (ValueError, TypeError, OSError):
                    pass

            if not auto_mgmt:
                issues.append("automatic_management_disabled")

            # Check for usage — last accessed
            last_used = account.get("lastUsedDate")
            if last_used:
                try:
                    last_used_dt = datetime.fromtimestamp(last_used, tz=timezone.utc)
                    if last_used_dt < rotation_threshold:
                        issues.append("unused_90_days")
                except (ValueError, TypeError, OSError):
                    pass

            severity = "info"
            obs_type = "inventory"
            if "password_overdue_90_days" in issues:
                severity = "high"
                obs_type = "policy_violation"
            elif "automatic_management_disabled" in issues:
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Privileged account: {name}" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "account_id": account.get("id", ""),
                    "name": name,
                    "platform_id": platform_id,
                    "safe_name": safe_name,
                    "auto_management": auto_mgmt,
                    "last_modified": last_modified,
                    "last_used": last_used,
                    "issues": issues,
                },
                resource_id=account.get("id", ""),
                resource_type="cyberark_account",
                resource_name=name,
                severity=severity,
            ))

        return findings

    # -- Safes --

    def _normalize_safes(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        safes = raw.raw_data.get("response", [])

        for safe in safes:
            name = safe.get("safeName", safe.get("SafeName", "unknown"))
            member_count = safe.get("numberOfMembers", safe.get("NumberOfMembers", 0))

            issues = []
            if member_count == 0:
                issues.append("no_members")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Safe: {name}" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "safe_name": name,
                    "member_count": member_count,
                    "issues": issues,
                    "safe": safe,
                },
                resource_id=safe.get("safeUrlId", safe.get("SafeUrlId", name)),
                resource_type="cyberark_safe",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- Platforms --

    def _normalize_platforms(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        platforms = raw.raw_data.get("response", [])

        for platform in platforms:
            name = platform.get("Name", platform.get("PlatformID", "unknown"))
            active = platform.get("Active", True)

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Platform: {name}" + (" — inactive" if not active else ""),
                detail=platform,
                resource_id=platform.get("PlatformID", name),
                resource_type="cyberark_platform",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- Session Recordings --

    def _normalize_recordings(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        recordings = raw.raw_data.get("response", [])

        for recording in recordings:
            user = recording.get("User", "unknown")
            target = recording.get("AccountUserName", "unknown")
            duration = recording.get("Duration", 0)

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Session recording: {user} → {target}",
                detail={
                    "user": user,
                    "target": target,
                    "duration_seconds": duration,
                    "start_time": recording.get("Start", ""),
                    "recording": recording,
                },
                resource_id=recording.get("SessionID", ""),
                resource_type="cyberark_session",
                resource_name=f"{user} → {target}",
                severity="info",
            ))

        return findings

    # -- Password Compliance --

    def _normalize_password_compliance(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        accounts = raw.raw_data.get("response", [])
        now = datetime.now(timezone.utc)

        overdue_count = 0
        for account in accounts:
            secret_mgmt = account.get("secretManagement", {})
            last_modified = secret_mgmt.get("lastModifiedTime")
            status = secret_mgmt.get("status", "")

            if last_modified:
                try:
                    last_mod_dt = datetime.fromtimestamp(last_modified, tz=timezone.utc)
                    days_since = (now - last_mod_dt).days
                    if days_since > 90:
                        overdue_count += 1
                except (ValueError, TypeError, OSError):
                    pass

        severity = "info"
        obs_type = "inventory"
        issues = []
        if overdue_count > 0:
            issues.append(f"{overdue_count}_accounts_overdue")
            severity = "high" if overdue_count > 10 else "medium"
            obs_type = "policy_violation"

        findings.append(FindingData(
            **self._base(raw),
            observation_type=obs_type,
            title=f"Password compliance summary — {overdue_count}/{len(accounts)} overdue",
            detail={
                "total_accounts": len(accounts),
                "overdue_count": overdue_count,
                "issues": issues,
            },
            resource_id="cyberark_password_compliance",
            resource_type="cyberark_compliance",
            resource_name="password_compliance",
            severity=severity,
        ))

        return findings


# Register
registry.register(CyberArkNormalizer())
