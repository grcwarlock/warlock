"""Alibaba Cloud normalizer — transforms raw Alibaba API responses into Findings.

Each event_type gets a handler that knows the shape of that specific API
response and extracts structured observations from it.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AlibabaNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "ali_security_alerts": "_normalize_security_alerts",
        "ali_ram_users": "_normalize_ram_users",
        "ali_actiontrail_events": "_normalize_actiontrail_events",
        "ali_security_groups": "_normalize_security_groups",
        "ali_kms_keys": "_normalize_kms_keys",
        "ali_config_compliance": "_normalize_config_compliance",
        "ali_oss_buckets": "_normalize_oss_buckets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "alibaba" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Alibaba findings."""
        return {
            "raw_event_id": raw.id,
            "source": "alibaba",
            "source_type": SourceType.CLOUD,
            "provider": "alibaba",
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- Security Center Alerts --

    def _normalize_security_alerts(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        alerts = response.get("alerts", [])

        severity_map = {
            "serious": "critical",
            "suspicious": "high",
            "remind": "medium",
        }

        for alert in alerts:
            ali_level = alert.get("Level", "").lower()
            mapped_severity = severity_map.get(ali_level, "info")
            alarm_name = alert.get("AlarmEventName", alert.get("Name", "unknown"))
            instance_name = alert.get("InstanceName", "")
            alarm_type = alert.get("AlarmEventType", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"Alibaba Security Center: {alarm_name}",
                detail={
                    "alarm_event_name": alarm_name,
                    "alarm_event_type": alarm_type,
                    "level": alert.get("Level", ""),
                    "instance_name": instance_name,
                    "instance_id": alert.get("InstanceId", ""),
                    "internet_ip": alert.get("InternetIp", ""),
                    "intranet_ip": alert.get("IntranetIp", ""),
                    "description": alert.get("Description", ""),
                    "solution": alert.get("Solution", ""),
                    "can_cancel_fault": alert.get("CanCancelFault", False),
                    "uuid": alert.get("Uuid", ""),
                },
                resource_id=alert.get("InstanceId", ""),
                resource_type="ecs_instance",
                resource_name=instance_name,
                severity=mapped_severity,
            ))

        return findings

    # -- RAM Users --

    def _normalize_ram_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        users = response.get("users", [])

        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(days=90)

        for user in users:
            user_name = user.get("UserName", "unknown")
            user_id = user.get("UserId", "")
            issues = []
            severity = "info"

            # Check MFA status
            mfa_device = user.get("MFADevice", {})
            has_mfa = bool(mfa_device.get("SerialNumber", ""))
            if not has_mfa:
                issues.append("mfa_not_enabled")
                severity = "high"

            # Check for stale users (no recent login)
            last_login = user.get("LastLoginDate", "")
            if last_login:
                try:
                    login_dt = datetime.fromisoformat(
                        last_login.replace("Z", "+00:00")
                    )
                    if login_dt < stale_threshold:
                        issues.append(f"stale_user_last_login_{last_login}")
                        if severity != "high":
                            severity = "medium"
                except (ValueError, TypeError):
                    pass
            else:
                # Never logged in — could be stale
                create_date = user.get("CreateDate", "")
                if create_date:
                    try:
                        create_dt = datetime.fromisoformat(
                            create_date.replace("Z", "+00:00")
                        )
                        if create_dt < stale_threshold:
                            issues.append("never_logged_in_stale")
                            if severity != "high":
                                severity = "medium"
                    except (ValueError, TypeError):
                        pass

            obs_type = "inventory"
            if issues:
                obs_type = "misconfiguration" if "mfa_not_enabled" in issues else "inventory"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"RAM user: {user_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "user_name": user_name,
                    "user_id": user_id,
                    "display_name": user.get("DisplayName", ""),
                    "create_date": user.get("CreateDate", ""),
                    "last_login_date": last_login,
                    "has_mfa": has_mfa,
                    "mfa_serial": mfa_device.get("SerialNumber", ""),
                    "issues": issues,
                },
                resource_id=user_id,
                resource_type="ram_user",
                resource_name=user_name,
                severity=severity,
            ))

        return findings

    # -- ActionTrail Events --

    def _normalize_actiontrail_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        events = response.get("events", [])

        # Actions that indicate privilege escalation
        escalation_actions = {
            "AttachPolicyToUser", "AttachPolicyToGroup", "AttachPolicyToRole",
            "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
            "CreateRole", "AssumeRole", "CreateAccessKey",
            "UpdateRole", "CreateUser",
        }

        for event in events:
            event_name = event.get("eventName", event.get("EventName", ""))
            event_source = event.get("eventSource", event.get("EventSource", ""))
            error_code = event.get("errorCode", event.get("ErrorCode", ""))
            error_message = event.get("errorMessage", event.get("ErrorMessage", ""))
            user_identity = event.get("userIdentity", event.get("UserIdentity", {}))

            # Determine severity and whether to emit a finding
            severity = "info"
            obs_type = "inventory"

            if error_code or error_message:
                severity = "medium"
                obs_type = "alert"

            if event_name in escalation_actions:
                severity = "high"
                obs_type = "alert"

            # Skip low-noise info-level events
            if severity == "info":
                continue

            principal = (
                user_identity.get("principalId", "")
                or user_identity.get("PrincipalId", "")
            )
            user_name = (
                user_identity.get("userName", "")
                or user_identity.get("UserName", "")
            )

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"ActionTrail: {event_name}" + (
                    f" — error: {error_code}" if error_code else ""
                ),
                detail={
                    "event_name": event_name,
                    "event_source": event_source,
                    "event_time": event.get("eventTime", event.get("EventTime", "")),
                    "error_code": error_code,
                    "error_message": error_message,
                    "source_ip": event.get("sourceIpAddress", event.get("SourceIpAddress", "")),
                    "user_agent": event.get("userAgent", event.get("UserAgent", "")),
                    "principal_id": principal,
                    "user_name": user_name,
                    "request_params": event.get("requestParameters", event.get("RequestParameters", {})),
                    "is_privilege_escalation": event_name in escalation_actions,
                },
                resource_id=event.get("resourceId", event.get("ResourceId", "")),
                resource_type=event.get("resourceType", event.get("ResourceType", "alibaba_resource")),
                resource_name=event_name,
                severity=severity,
                account_id=event.get("accountId", event.get("AccountId", "")),
            ))

        return findings

    # -- Security Groups --

    def _normalize_security_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        groups = response.get("security_groups", [])

        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 8080, 443}

        for sg in groups:
            sg_id = sg.get("SecurityGroupId", "")
            sg_name = sg.get("SecurityGroupName", sg_id)
            rules = sg.get("Rules", [])
            issues = []

            for rule in rules:
                direction = rule.get("Direction", "")
                if direction.lower() != "ingress":
                    continue

                source_cidr = rule.get("SourceCidrIp", "")
                if source_cidr != "0.0.0.0/0":
                    continue

                port_range = rule.get("PortRange", "")
                policy = rule.get("Policy", "")
                if policy.lower() != "accept":
                    continue

                if port_range == "-1/-1" or port_range == "1/65535":
                    issues.append("all_ports_open_to_internet")
                elif "/" in port_range:
                    try:
                        start_port, end_port = port_range.split("/")
                        start_p, end_p = int(start_port), int(end_port)
                        for p in sensitive_ports:
                            if start_p <= p <= end_p:
                                issues.append(f"open_to_internet_port_{p}")
                    except (ValueError, TypeError):
                        pass

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"
                if "all_ports_open_to_internet" in issues:
                    severity = "critical"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Security group: {sg_name}" + (
                    f" — {len(issues)} open ingress issues" if issues else ""
                ),
                detail={
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "vpc_id": sg.get("VpcId", ""),
                    "rule_count": len(rules),
                    "issues": issues,
                    "rules": rules,
                },
                resource_id=sg_id,
                resource_type="ecs_security_group",
                resource_name=sg_name,
                severity=severity,
            ))

        return findings

    # -- KMS Keys --

    def _normalize_kms_keys(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        keys = response.get("keys", [])

        for key in keys:
            key_id = key.get("KeyId", "")
            metadata = key.get("KeyMetadata", {})
            key_state = metadata.get("KeyState", "Unknown")
            creator = metadata.get("Creator", "")
            description = metadata.get("Description", "")
            key_usage = metadata.get("KeyUsage", "")
            rotation_interval = metadata.get("AutomaticRotation", "")

            issues = []
            severity = "info"

            if key_state == "Disabled":
                issues.append("key_disabled")
                severity = "medium"
            elif key_state == "PendingDeletion":
                issues.append("key_pending_deletion")
                severity = "high"
            elif key_state == "PendingImport":
                issues.append("key_pending_import")
                severity = "low"

            # Check for missing rotation
            if (
                key_state == "Enabled"
                and rotation_interval in ("Disabled", "")
                and key_usage in ("ENCRYPT/DECRYPT", "")
            ):
                issues.append("automatic_rotation_disabled")
                if severity == "info":
                    severity = "medium"

            obs_type = "inventory"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"KMS key: {key_id}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "key_id": key_id,
                    "key_state": key_state,
                    "creator": creator,
                    "description": description,
                    "key_usage": key_usage,
                    "creation_date": metadata.get("CreationDate", ""),
                    "delete_date": metadata.get("DeleteDate", ""),
                    "automatic_rotation": rotation_interval,
                    "origin": metadata.get("Origin", ""),
                    "key_spec": metadata.get("KeySpec", ""),
                    "issues": issues,
                },
                resource_id=key_id,
                resource_type="kms_key",
                resource_name=description or key_id,
                severity=severity,
            ))

        return findings

    # -- Cloud Config Compliance --

    def _normalize_config_compliance(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        results = response.get("results", [])

        for result in results:
            compliance_type = result.get("ComplianceType", "")
            resource_id = result.get("ResourceId", "")
            resource_type = result.get("ResourceType", "")
            risk_level = result.get("RiskLevel", 0)
            config_rule_name = result.get("ConfigRuleName", "")
            annotation = result.get("Annotation", "")

            # Only emit findings for non-compliant resources
            if compliance_type.upper() == "COMPLIANT":
                continue

            # Map risk level to severity (1=high, 2=medium, 3=low in Alibaba)
            risk_severity_map = {
                1: "high",
                2: "medium",
                3: "low",
            }
            severity = risk_severity_map.get(risk_level, "medium")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="policy_violation",
                title=f"Config non-compliant: {config_rule_name}",
                detail={
                    "config_rule_name": config_rule_name,
                    "config_rule_id": result.get("ConfigRuleId", ""),
                    "compliance_pack_id": result.get("CompliancePackId", ""),
                    "compliance_type": compliance_type,
                    "risk_level": risk_level,
                    "annotation": annotation,
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "invocation_time": result.get("InvocationTime", ""),
                },
                resource_id=resource_id,
                resource_type=resource_type or "alibaba_resource",
                resource_name=resource_id,
                severity=severity,
            ))

        return findings

    # -- OSS Buckets --

    def _normalize_oss_buckets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        buckets = response.get("buckets", [])

        public_acl_values = {"public-read", "public-read-write"}

        for bucket in buckets:
            bucket_name = bucket.get("Name", "unknown")
            acl_info = bucket.get("ACL", {})
            encryption_info = bucket.get("Encryption", {})
            issues = []
            severity = "info"

            # Check ACL for public access
            grant = acl_info.get("Grant", "")
            access_control = acl_info.get("AccessControlList", {})
            effective_grant = grant or access_control.get("Grant", "")

            if effective_grant.lower() in public_acl_values:
                issues.append(f"public_acl_{effective_grant}")
                severity = "critical" if effective_grant.lower() == "public-read-write" else "high"

            # Check encryption
            has_encryption = bool(
                encryption_info.get("SSEAlgorithm", "")
                or encryption_info.get("ServerSideEncryptionRule", {})
                   .get("ApplyServerSideEncryptionByDefault", {})
                   .get("SSEAlgorithm", "")
            )
            if not has_encryption:
                issues.append("server_side_encryption_missing")
                if severity == "info":
                    severity = "medium"

            obs_type = "inventory"
            if issues:
                obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"OSS bucket: {bucket_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "bucket_name": bucket_name,
                    "location": bucket.get("Location", ""),
                    "creation_date": bucket.get("CreationDate", ""),
                    "acl": effective_grant,
                    "has_encryption": has_encryption,
                    "encryption_info": encryption_info,
                    "issues": issues,
                },
                resource_id=f"oss://{bucket_name}",
                resource_type="oss_bucket",
                resource_name=bucket_name,
                severity=severity,
            ))

        return findings


# Register
registry.register(AlibabaNormalizer())
