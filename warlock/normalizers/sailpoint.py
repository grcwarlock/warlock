"""SailPoint normalizer — transforms raw SailPoint API responses into Findings.

Normalizes certification campaign status, orphan accounts, and
excessive entitlements.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class SailPointNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "sailpoint_identities": "_normalize_identities",
        "sailpoint_certifications": "_normalize_certifications",
        "sailpoint_roles": "_normalize_roles",
        "sailpoint_entitlements": "_normalize_entitlements",
        "sailpoint_accounts": "_normalize_accounts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "sailpoint" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all SailPoint findings."""
        return {
            "raw_event_id": raw.id,
            "source": "sailpoint",
            "source_type": SourceType.IAM,
            "provider": "sailpoint",
            "account_id": raw.raw_data.get("tenant", ""),
            "region": "",
            "observed_at": raw.observed_at,
        }

    # -- Identities --

    def _normalize_identities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        identities = raw.raw_data.get("response", [])

        for identity in identities:
            name = identity.get("name", "unknown")
            alias = identity.get("alias", "")
            status = identity.get("status", "")
            is_active = identity.get("isActive", True)
            account_count = identity.get("accountCount", 0)
            entitlement_count = identity.get("entitlementCount", 0)

            issues = []
            if not is_active:
                issues.append("inactive_identity")
            if entitlement_count > 50:
                issues.append(f"excessive_entitlements_{entitlement_count}")
            if account_count > 10:
                issues.append(f"excessive_accounts_{account_count}")

            severity = "info"
            obs_type = "inventory"
            if "excessive_entitlements" in str(issues):
                severity = "medium"
                obs_type = "access_anomaly"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Identity: {name}" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "identity_id": identity.get("id", ""),
                    "name": name,
                    "alias": alias,
                    "status": status,
                    "is_active": is_active,
                    "account_count": account_count,
                    "entitlement_count": entitlement_count,
                    "issues": issues,
                },
                resource_id=identity.get("id", ""),
                resource_type="sailpoint_identity",
                resource_name=name,
                severity=severity,
            ))

        return findings

    # -- Certifications (Access Review Campaigns) --

    def _normalize_certifications(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        campaigns = raw.raw_data.get("response", [])

        for campaign in campaigns:
            name = campaign.get("name", "unknown")
            status = campaign.get("status", "")
            campaign_type = campaign.get("type", "")
            deadline = campaign.get("deadline", "")
            completed = campaign.get("completedCount", 0)
            total = campaign.get("totalCount", 0)

            issues = []
            if status == "STAGED":
                issues.append("campaign_not_started")
            elif status == "ACTIVE":
                # Check if overdue
                if deadline:
                    try:
                        deadline_dt = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
                        if deadline_dt < datetime.now(timezone.utc):
                            issues.append("campaign_overdue")
                    except (ValueError, TypeError):
                        pass

                # Check completion rate
                if total > 0:
                    completion_rate = completed / total
                    if completion_rate < 0.5:
                        issues.append(f"low_completion_{int(completion_rate * 100)}pct")

            severity = "info"
            obs_type = "inventory"
            if "campaign_overdue" in issues:
                severity = "high"
                obs_type = "policy_violation"
            elif "low_completion" in str(issues):
                severity = "medium"
                obs_type = "policy_violation"
            elif "campaign_not_started" in issues:
                severity = "low"
                obs_type = "policy_violation"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Certification: {name}" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "campaign_id": campaign.get("id", ""),
                    "name": name,
                    "status": status,
                    "type": campaign_type,
                    "deadline": deadline,
                    "completed": completed,
                    "total": total,
                    "issues": issues,
                },
                resource_id=campaign.get("id", ""),
                resource_type="sailpoint_certification",
                resource_name=name,
                severity=severity,
            ))

        return findings

    # -- Roles --

    def _normalize_roles(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        roles = raw.raw_data.get("response", [])

        for role in roles:
            name = role.get("name", "unknown")
            requestable = role.get("requestable", False)
            enabled = role.get("enabled", True)
            membership_count = role.get("membershipCount", 0)

            findings.append(FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"Role: {name}",
                detail={
                    "role_id": role.get("id", ""),
                    "name": name,
                    "requestable": requestable,
                    "enabled": enabled,
                    "membership_count": membership_count,
                    "role": role,
                },
                resource_id=role.get("id", ""),
                resource_type="sailpoint_role",
                resource_name=name,
                severity="info",
            ))

        return findings

    # -- Entitlements --

    def _normalize_entitlements(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        entitlements = raw.raw_data.get("response", [])

        for entitlement in entitlements:
            name = entitlement.get("name", "unknown")
            source_name = entitlement.get("source", {}).get("name", "unknown")
            privileged = entitlement.get("privileged", False)
            owner = entitlement.get("owner", {})

            issues = []
            if privileged and not owner:
                issues.append("privileged_no_owner")
            if not owner:
                issues.append("no_owner")

            severity = "info"
            obs_type = "inventory"
            if "privileged_no_owner" in issues:
                severity = "high"
                obs_type = "access_anomaly"
            elif privileged:
                severity = "low"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Entitlement: {name} ({source_name})" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "entitlement_id": entitlement.get("id", ""),
                    "name": name,
                    "source_name": source_name,
                    "privileged": privileged,
                    "owner": owner,
                    "issues": issues,
                },
                resource_id=entitlement.get("id", ""),
                resource_type="sailpoint_entitlement",
                resource_name=name,
                severity=severity,
            ))

        return findings

    # -- Accounts --

    def _normalize_accounts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        accounts = raw.raw_data.get("response", [])

        for account in accounts:
            name = account.get("name", "unknown")
            source_name = account.get("sourceName", "unknown")
            identity_id = account.get("identityId", "")
            disabled = account.get("disabled", False)
            uncorrelated = account.get("uncorrelated", False)

            issues = []
            if uncorrelated:
                issues.append("orphan_account")
            if disabled and identity_id:
                issues.append("disabled_with_identity")

            severity = "info"
            obs_type = "inventory"
            if "orphan_account" in issues:
                severity = "high"
                obs_type = "access_anomaly"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Account: {name} ({source_name})" + (f" — {', '.join(issues)}" if issues else ""),
                detail={
                    "account_id": account.get("id", ""),
                    "name": name,
                    "source_name": source_name,
                    "identity_id": identity_id,
                    "disabled": disabled,
                    "uncorrelated": uncorrelated,
                    "issues": issues,
                },
                resource_id=account.get("id", ""),
                resource_type="sailpoint_account",
                resource_name=name,
                severity=severity,
            ))

        return findings


# Register
registry.register(SailPointNormalizer())
