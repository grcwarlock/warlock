"""Azure normalizer — transforms raw Azure API responses into Findings.

Each event_type gets a normalizer function that knows the shape of that
specific API response and extracts structured observations from it.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AzureNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "policy_compliance": "_normalize_policy_compliance",
        "defender_alerts": "_normalize_defender_alerts",
        "entra_sign_ins": "_normalize_entra_sign_ins",
        "network_security_groups": "_normalize_nsgs",
        "key_vault": "_normalize_key_vault",
        "storage_accounts": "_normalize_storage_accounts",
        "activity_log": "_normalize_activity_log",
        "monitor_alerts": "_normalize_monitor_alerts",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "azure" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Azure findings."""
        return {
            "raw_event_id": raw.id,
            "source": "azure",
            "source_type": SourceType.CLOUD,
            "provider": "azure",
            "account_id": raw.raw_data.get("subscription_id", ""),
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Policy Compliance --

    def _normalize_policy_compliance(self, raw: RawEventData) -> list[FindingData]:
        """One finding per non-compliant policy state."""
        findings = []
        response = raw.raw_data.get("response", {})
        states = response.get("policy_states", [])

        for state in states:
            compliance = state.get("compliance_state", "").lower()
            if compliance == "compliant":
                continue

            policy_name = state.get("policy_definition_name", "unknown")
            resource_id = state.get("resource_id", "")

            severity = "medium"
            if state.get("policy_definition_group_names"):
                groups = state.get("policy_definition_group_names", [])
                if any("security" in g.lower() for g in groups):
                    severity = "high"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="policy_violation",
                    title=f"Non-compliant policy: {policy_name}",
                    detail={
                        "policy_definition_name": policy_name,
                        "policy_assignment_name": state.get("policy_assignment_name", ""),
                        "compliance_state": compliance,
                        "resource_id": resource_id,
                        "resource_type": state.get("resource_type", ""),
                        "policy_definition_group_names": state.get(
                            "policy_definition_group_names", []
                        ),
                    },
                    resource_id=resource_id,
                    resource_type=state.get("resource_type", "azure_resource"),
                    resource_name=state.get("resource_name", ""),
                    severity=severity,
                )
            )

        return findings

    # -- Defender for Cloud --

    def _normalize_defender_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        alerts = response.get("alerts", [])

        severity_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
        }

        for alert in alerts:
            alert_severity = alert.get("properties", {}).get("severity", "medium").lower()
            mapped_severity = severity_map.get(alert_severity, "medium")
            alert_name = alert.get("properties", {}).get("alertDisplayName", "Unknown alert")
            resource_id = alert.get("properties", {}).get("compromisedEntity", alert.get("id", ""))

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Defender alert: {alert_name}",
                    detail={
                        "alert_type": alert.get("properties", {}).get("alertType", ""),
                        "alert_display_name": alert_name,
                        "description": alert.get("properties", {}).get("description", ""),
                        "status": alert.get("properties", {}).get("status", ""),
                        "compromised_entity": resource_id,
                        "intent": alert.get("properties", {}).get("intent", ""),
                    },
                    resource_id=resource_id,
                    resource_type="azure_defender_alert",
                    resource_name=alert_name,
                    severity=mapped_severity,
                )
            )

        return findings

    # -- Entra ID Sign-ins --

    def _normalize_entra_sign_ins(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        sign_ins = response.get("value", [])

        for sign_in in sign_ins:
            status = sign_in.get("status", {})
            error_code = status.get("errorCode", 0)
            user = sign_in.get("userPrincipalName", "unknown")

            if error_code == 0:
                # Successful sign-in — only flag risky ones
                risk_level = sign_in.get("riskLevelDuringSignIn", "none")
                if risk_level in ("none", "low"):
                    continue
                severity = "high" if risk_level == "high" else "medium"
                obs_type = "access_anomaly"
                title = f"Risky sign-in: {user} — risk={risk_level}"
            else:
                # Failed sign-in
                severity = "info"
                obs_type = "inventory"
                title = f"Failed sign-in: {user} — error={error_code}"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=title,
                    detail={
                        "user_principal_name": user,
                        "app_display_name": sign_in.get("appDisplayName", ""),
                        "ip_address": sign_in.get("ipAddress", ""),
                        "location": sign_in.get("location", {}),
                        "risk_level": sign_in.get("riskLevelDuringSignIn", "none"),
                        "error_code": error_code,
                        "failure_reason": status.get("failureReason", ""),
                        "conditional_access_status": sign_in.get("conditionalAccessStatus", ""),
                    },
                    resource_id=sign_in.get("userId", ""),
                    resource_type="entra_user",
                    resource_name=user,
                    severity=severity,
                )
            )

        return findings

    # -- Network Security Groups --

    def _normalize_nsgs(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        nsgs = response.get("network_security_groups", [])
        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379}

        for nsg in nsgs:
            issues = []
            rules = nsg.get("security_rules", [])

            for rule in rules:
                if rule.get("direction", "").lower() != "inbound":
                    continue
                if rule.get("access", "").lower() != "allow":
                    continue

                source_prefix = rule.get("source_address_prefix", "")
                if source_prefix not in ("*", "0.0.0.0/0", "Internet"):
                    continue

                dest_port = rule.get("destination_port_range", "")
                if dest_port == "*":
                    issues.append("all_ports_open_to_internet")
                else:
                    try:
                        port = int(dest_port)
                        if port in sensitive_ports:
                            issues.append(f"open_to_internet_port_{port}")
                    except (ValueError, TypeError):
                        # Port range like "80-443"
                        pass

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"

            nsg_name = nsg.get("name", "unknown")
            nsg_id = nsg.get("id", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"NSG {nsg_name}" + (f" — {len(issues)} open ports" if issues else ""),
                    detail={"nsg": nsg, "issues": issues},
                    resource_id=nsg_id,
                    resource_type="network_security_group",
                    resource_name=nsg_name,
                    severity=severity,
                )
            )

        return findings

    # -- Key Vault --

    def _normalize_key_vault(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        vaults = response.get("vaults", [])

        for vault in vaults:
            vault_name = vault.get("name", "unknown")
            vault_id = vault.get("id", "")
            properties = vault.get("properties", {})

            issues = []
            if not properties.get("enable_soft_delete", False):
                issues.append("soft_delete_disabled")
            if not properties.get("enable_purge_protection", False):
                issues.append("purge_protection_disabled")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "medium"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Key Vault: {vault_name}"
                    + (f" — {', '.join(issues)}" if issues else ""),
                    detail={"vault": vault, "issues": issues},
                    resource_id=vault_id,
                    resource_type="key_vault",
                    resource_name=vault_name,
                    severity=severity,
                )
            )

        return findings

    # -- Storage Accounts --

    def _normalize_storage_accounts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        accounts = response.get("storage_accounts", [])

        for account in accounts:
            account_name = account.get("name", "unknown")
            account_id = account.get("id", "")
            properties = account.get("properties", {})

            issues = []
            if not properties.get("supports_https_traffic_only", True):
                issues.append("https_not_required")
            encryption = properties.get("encryption", {})
            if not encryption.get("require_infrastructure_encryption", False):
                issues.append("no_infrastructure_encryption")
            network_rules = properties.get("network_rule_set", {})
            if network_rules.get("default_action", "").lower() == "allow":
                issues.append("default_network_access_allow")
            if properties.get("allow_blob_public_access") is not False:
                # Only flag if explicitly set to True
                if properties.get("allow_blob_public_access", False):
                    issues.append("public_blob_access_enabled")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "medium"
                obs_type = "misconfiguration"
                if "https_not_required" in issues or "public_blob_access_enabled" in issues:
                    severity = "high"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Storage account: {account_name}"
                    + (f" — {len(issues)} issues" if issues else ""),
                    detail={"storage_account": account, "issues": issues},
                    resource_id=account_id,
                    resource_type="storage_account",
                    resource_name=account_name,
                    severity=severity,
                )
            )

        return findings

    # -- Activity Log --

    def _normalize_activity_log(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        logs = response.get("activity_logs", [])

        for entry in logs:
            level = entry.get("level", "").lower()
            if level not in ("error", "critical", "warning"):
                continue

            severity_map = {"critical": "critical", "error": "high", "warning": "medium"}
            severity = severity_map.get(level, "info")
            operation = entry.get("operation_name", {})
            op_value = operation.get("value", "") if isinstance(operation, dict) else str(operation)

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Activity log: {op_value}" + (f" — {level}" if level else ""),
                    detail={
                        "operation": op_value,
                        "level": level,
                        "caller": entry.get("caller", ""),
                        "status": entry.get("status", {}),
                        "resource_id": entry.get("resource_id", ""),
                        "event_timestamp": entry.get("event_timestamp", ""),
                    },
                    resource_id=entry.get("resource_id", ""),
                    resource_type="azure_activity",
                    resource_name=op_value,
                    severity=severity,
                )
            )

        return findings

    # -- Azure Monitor --

    def _normalize_monitor_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        alerts = response.get("alerts", [])

        severity_map = {
            "sev0": "critical",
            "sev1": "high",
            "sev2": "medium",
            "sev3": "low",
            "sev4": "info",
        }

        for alert in alerts:
            properties = alert.get("properties", {})
            alert_severity = properties.get("severity", "Sev3").lower()
            mapped_severity = severity_map.get(alert_severity, "medium")
            alert_name = properties.get("alert_rule", "Unknown alert")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Monitor alert: {alert_name}",
                    detail={
                        "alert_rule": alert_name,
                        "severity": alert_severity,
                        "monitor_condition": properties.get("monitor_condition", ""),
                        "target_resource": properties.get("target_resource", ""),
                        "target_resource_type": properties.get("target_resource_type", ""),
                        "signal_type": properties.get("signal_type", ""),
                        "description": properties.get("description", ""),
                    },
                    resource_id=properties.get("target_resource", alert.get("id", "")),
                    resource_type=properties.get("target_resource_type", "azure_monitor"),
                    resource_name=alert_name,
                    severity=mapped_severity,
                )
            )

        return findings


# Register
registry.register(AzureNormalizer())
