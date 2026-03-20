"""OCI normalizer — transforms raw OCI API responses into Findings.

Each event_type gets a normalizer function that knows the shape of that
specific API response and extracts structured observations from it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class OCINormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "oci_cloud_guard_problems": "_normalize_cloud_guard_problems",
        "oci_iam_users": "_normalize_iam_users",
        "oci_iam_groups": "_normalize_iam_groups",
        "oci_audit_events": "_normalize_audit_events",
        "oci_vulnerabilities": "_normalize_vulnerabilities",
        "oci_security_lists": "_normalize_security_lists",
        "oci_vaults": "_normalize_vaults",
        "oci_bastions": "_normalize_bastions",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "oci" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all OCI findings."""
        return {
            "raw_event_id": raw.id,
            "source": "oci",
            "source_type": SourceType.CLOUD,
            "provider": "oci",
            "account_id": raw.raw_data.get("tenancy_id", ""),
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Cloud Guard Problems --

    def _normalize_cloud_guard_problems(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        problems = response.get("problems", [])

        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
        }

        for problem in problems:
            risk_level = problem.get("riskLevel", "MEDIUM")
            mapped_severity = severity_map.get(risk_level, "medium")
            detector_id = problem.get("detectorId", "")
            resource_id = problem.get("resourceId", "")
            resource_name = problem.get("resourceName", "")
            resource_type = problem.get("resourceType", "oci_resource")
            labels = problem.get("labels", [])

            obs_type = "misconfiguration"
            if detector_id.startswith("ACTIVITY"):
                obs_type = "alert"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Cloud Guard: {problem.get('detectorRuleId', 'unknown')} — {risk_level}",
                    detail={
                        "problem_id": problem.get("id", ""),
                        "detector_id": detector_id,
                        "detector_rule_id": problem.get("detectorRuleId", ""),
                        "risk_level": risk_level,
                        "lifecycle_state": problem.get("lifecycleState", ""),
                        "resource_id": resource_id,
                        "resource_type": resource_type,
                        "resource_name": resource_name,
                        "labels": labels,
                        "recommendation": problem.get("recommendation", ""),
                        "target_id": problem.get("targetId", ""),
                        "compartment_id": problem.get("compartmentId", ""),
                    },
                    resource_id=resource_id,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    severity=mapped_severity,
                )
            )

        return findings

    # -- IAM Users --

    def _normalize_iam_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        users = response.get("users", [])
        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=90)

        for user in users:
            user_name = user.get("name", "unknown")
            user_id = user.get("id", "")
            lifecycle_state = user.get("lifecycleState", "")

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Check MFA status
            if not user.get("isMfaActivated", False):
                issues.append("mfa_not_enabled")

            # Check for stale users (no activity in 90+ days)
            last_login = user.get("lastSuccessfulLoginTime")
            if last_login:
                try:
                    if isinstance(last_login, str):
                        login_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                    else:
                        login_dt = last_login
                    if login_dt < stale_threshold:
                        issues.append("stale_user_90_days")
                except (ValueError, TypeError):
                    pass
            else:
                # Never logged in — check creation time
                created = user.get("timeCreated", "")
                if created:
                    try:
                        if isinstance(created, str):
                            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        else:
                            created_dt = created
                        if created_dt < stale_threshold:
                            issues.append("never_logged_in_stale")
                    except (ValueError, TypeError):
                        pass

            # Check if user is blocked or inactive
            if lifecycle_state == "BLOCKED":
                issues.append("user_blocked")
            elif lifecycle_state == "INACTIVE":
                issues.append("user_inactive")

            if issues:
                obs_type = "misconfiguration"
                if "mfa_not_enabled" in issues:
                    severity = "high"
                elif "stale_user_90_days" in issues or "never_logged_in_stale" in issues:
                    severity = "medium"
                else:
                    severity = "low"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"IAM user: {user_name}" + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "user_id": user_id,
                        "user_name": user_name,
                        "email": user.get("email", ""),
                        "lifecycle_state": lifecycle_state,
                        "is_mfa_activated": user.get("isMfaActivated", False),
                        "time_created": user.get("timeCreated", ""),
                        "last_successful_login_time": last_login or "",
                        "capabilities": user.get("capabilities", {}),
                        "issues": issues,
                    },
                    resource_id=user_id,
                    resource_type="oci_user",
                    resource_name=user_name,
                    severity=severity,
                )
            )

        return findings

    # -- IAM Groups --

    def _normalize_iam_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        groups = response.get("groups", [])

        for group in groups:
            group_name = group.get("name", "unknown")
            group_id = group.get("id", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"IAM group: {group_name}",
                    detail={
                        "group_id": group_id,
                        "group_name": group_name,
                        "description": group.get("description", ""),
                        "lifecycle_state": group.get("lifecycleState", ""),
                        "time_created": group.get("timeCreated", ""),
                        "compartment_id": group.get("compartmentId", ""),
                    },
                    resource_id=group_id,
                    resource_type="oci_group",
                    resource_name=group_name,
                    severity="info",
                )
            )

        return findings

    # -- Audit Events --

    def _normalize_audit_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        events = response.get("audit_events", [])

        for event in events:
            data = event.get("data", event)
            response_info = data.get("response", data.get("responsePayload", {}))
            status = response_info.get("status", "")
            message = response_info.get("message", "")

            # Only flag failed/error events
            status_str = str(status)
            if status_str.startswith("2"):
                continue

            event_name = data.get("eventName", event.get("eventType", "unknown"))
            principal = data.get("identity", {}).get("principalName", "")
            resource_id = data.get("resourceId", "")

            severity = "info"
            if status_str.startswith("4"):
                severity = "medium"
                if status_str == "403":
                    severity = "high"
            elif status_str.startswith("5"):
                severity = "high"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="alert",
                    title=f"Audit event: {event_name} — status {status_str}",
                    detail={
                        "event_type": event.get("eventType", ""),
                        "event_name": event_name,
                        "source": event.get("source", ""),
                        "principal_name": principal,
                        "status": status_str,
                        "message": message,
                        "resource_id": resource_id,
                        "request_action": data.get("request", {}).get("action", ""),
                        "event_time": event.get("eventTime", ""),
                    },
                    resource_id=resource_id,
                    resource_type="oci_audit_event",
                    resource_name=event_name,
                    severity=severity,
                )
            )

        return findings

    # -- Vulnerability Scanning --

    def _normalize_vulnerabilities(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        vulns = response.get("vulnerabilities", [])

        for vuln in vulns:
            vuln_name = vuln.get("name", vuln.get("vulnerabilityId", "unknown"))
            host_id = vuln.get("hostId", vuln.get("instanceId", ""))
            cvss_score = vuln.get("cvssScore", vuln.get("score", 0.0))

            # Map CVSS to severity
            try:
                score = float(cvss_score)
            except (ValueError, TypeError):
                score = 0.0

            if score >= 9.0:
                severity = "critical"
            elif score >= 7.0:
                severity = "high"
            elif score >= 4.0:
                severity = "medium"
            elif score > 0.0:
                severity = "low"
            else:
                severity = "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="vulnerability",
                    title=f"Vulnerability: {vuln_name} — CVSS {score}",
                    detail={
                        "vulnerability_id": vuln.get("vulnerabilityId", ""),
                        "name": vuln_name,
                        "cvss_score": score,
                        "severity": vuln.get("severity", ""),
                        "host_id": host_id,
                        "state": vuln.get("state", ""),
                        "description": vuln.get("description", ""),
                        "cve_reference": vuln.get("cveReference", ""),
                        "package_name": vuln.get("packageName", ""),
                        "package_version": vuln.get("packageVersion", ""),
                        "fix_version": vuln.get("fixVersion", ""),
                    },
                    resource_id=host_id,
                    resource_type="oci_host",
                    resource_name=vuln_name,
                    severity=severity,
                )
            )

        return findings

    # -- Network Security Lists --

    def _normalize_security_lists(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        security_lists = response.get("security_lists", [])
        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 8080}

        for sec_list in security_lists:
            issues = []
            sl_name = sec_list.get("displayName", sec_list.get("display-name", "unknown"))
            sl_id = sec_list.get("id", "")

            ingress_rules = sec_list.get("ingressSecurityRules", [])
            for rule in ingress_rules:
                source = rule.get("source", "")
                if source != "0.0.0.0/0":
                    continue

                protocol = rule.get("protocol", "")
                # Protocol 6 = TCP, 17 = UDP, "all" = all
                if protocol == "all":
                    issues.append("all_protocols_open_to_internet")
                    continue

                tcp_options = rule.get("tcpOptions", {})
                udp_options = rule.get("udpOptions", {})
                port_range = tcp_options or udp_options

                if not port_range:
                    # No port restriction on this protocol
                    proto_name = (
                        "tcp" if protocol == "6" else "udp" if protocol == "17" else protocol
                    )
                    issues.append(f"all_{proto_name}_ports_open_to_internet")
                    continue

                dest_range = port_range.get("destinationPortRange", {})
                port_min = dest_range.get("min", 0)
                port_max = dest_range.get("max", 0)

                try:
                    port_min = int(port_min)
                    port_max = int(port_max)
                except (ValueError, TypeError):
                    continue

                for p in sensitive_ports:
                    if port_min <= p <= port_max:
                        issues.append(f"open_to_internet_port_{p}")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"
                if "all_protocols_open_to_internet" in issues:
                    severity = "critical"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Security list: {sl_name}"
                    + (f" — {len(issues)} open ports" if issues else ""),
                    detail={
                        "security_list_id": sl_id,
                        "display_name": sl_name,
                        "vcn_id": sec_list.get("vcnId", ""),
                        "lifecycle_state": sec_list.get("lifecycleState", ""),
                        "ingress_rule_count": len(ingress_rules),
                        "egress_rule_count": len(sec_list.get("egressSecurityRules", [])),
                        "issues": issues,
                    },
                    resource_id=sl_id,
                    resource_type="oci_security_list",
                    resource_name=sl_name,
                    severity=severity,
                )
            )

        return findings

    # -- Vault / Key Management --

    def _normalize_vaults(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        vaults = response.get("vaults", [])

        for vault in vaults:
            vault_name = vault.get("displayName", vault.get("display-name", "unknown"))
            vault_id = vault.get("id", "")
            lifecycle_state = vault.get("lifecycleState", "")

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Flag non-active lifecycle states
            if lifecycle_state in ("PENDING_DELETION", "SCHEDULING_DELETION"):
                issues.append("pending_deletion")
                severity = "medium"
                obs_type = "misconfiguration"
            elif lifecycle_state == "DELETED":
                issues.append("deleted")
            elif lifecycle_state == "CREATING":
                issues.append("still_creating")

            # Check vault type — DEFAULT vaults are less secure than VIRTUAL_PRIVATE
            vault_type = vault.get("vaultType", "")
            if vault_type == "DEFAULT":
                issues.append("shared_vault_partition")

            if issues and obs_type == "inventory":
                obs_type = "inventory"
                severity = "info"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Vault: {vault_name}" + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "vault_id": vault_id,
                        "display_name": vault_name,
                        "vault_type": vault_type,
                        "lifecycle_state": lifecycle_state,
                        "crypto_endpoint": vault.get("cryptoEndpoint", ""),
                        "management_endpoint": vault.get("managementEndpoint", ""),
                        "time_created": vault.get("timeCreated", ""),
                        "compartment_id": vault.get("compartmentId", ""),
                        "issues": issues,
                    },
                    resource_id=vault_id,
                    resource_type="oci_vault",
                    resource_name=vault_name,
                    severity=severity,
                )
            )

        return findings

    # -- Bastion Sessions --

    def _normalize_bastions(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        bastions = response.get("bastions", [])

        for bastion in bastions:
            bastion_name = bastion.get("name", bastion.get("displayName", "unknown"))
            bastion_id = bastion.get("id", "")
            lifecycle_state = bastion.get("lifecycleState", "")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Bastion: {bastion_name}",
                    detail={
                        "bastion_id": bastion_id,
                        "bastion_name": bastion_name,
                        "bastion_type": bastion.get("bastionType", ""),
                        "lifecycle_state": lifecycle_state,
                        "target_subnet_id": bastion.get("targetSubnetId", ""),
                        "target_vcn_id": bastion.get("targetVcnId", ""),
                        "client_cidr_block_allow_list": bastion.get("clientCidrBlockAllowList", []),
                        "max_session_ttl": bastion.get("maxSessionTtlInSeconds", 0),
                        "time_created": bastion.get("timeCreated", ""),
                        "compartment_id": bastion.get("compartmentId", ""),
                    },
                    resource_id=bastion_id,
                    resource_type="oci_bastion",
                    resource_name=bastion_name,
                    severity="info",
                )
            )

        return findings


# Register
registry.register(OCINormalizer())
