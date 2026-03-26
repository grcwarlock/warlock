"""AWS normalizer — transforms raw AWS API responses into Findings.

Each event_type gets a normalizer function that knows the shape of that
specific API response and extracts structured observations from it.
"""

from __future__ import annotations

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class AWSNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    # Map event_type → handler method name
    HANDLERS: dict[str, str] = {
        "iam_credential_report": "_normalize_credential_report",
        "iam_users": "_normalize_iam_users",
        "iam_password_policy": "_normalize_password_policy",
        "iam_account_summary": "_normalize_account_summary",
        "ec2_security_groups": "_normalize_security_groups",
        "ec2_network_acls": "_normalize_network_acls",
        "cloudtrail_trails": "_normalize_cloudtrail",
        "guardduty_detectors": "_normalize_guardduty",
        "securityhub_hub": "_normalize_securityhub",
        "s3_buckets": "_normalize_s3_buckets",
        "config_recorders": "_normalize_config_recorders",
        "config_compliance": "_normalize_config_compliance",
        "iam_policies": "_normalize_iam_policies",
        "ec2_vpcs": "_normalize_ec2_vpcs",
        "ec2_flow_logs": "_normalize_ec2_flow_logs",
        "cloudtrail_status": "_normalize_cloudtrail_status",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "aws" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all AWS findings."""
        return {
            "raw_event_id": raw.id,
            "source": "aws",
            "source_type": SourceType.CLOUD,
            "provider": "aws",
            "account_id": raw.raw_data.get("account_id", ""),
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- IAM --

    def _normalize_credential_report(self, raw: RawEventData) -> list[FindingData]:
        """One finding per IAM user from the credential report."""
        findings = []
        response = raw.raw_data.get("response", {})
        content = response.get("Content", "")

        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        if not content:
            return findings

        import csv
        from io import StringIO

        reader = csv.DictReader(StringIO(content))

        for row in reader:
            user = row.get("user", "unknown")
            mfa = row.get("mfa_active", "false").lower() == "true"
            has_password = row.get("password_enabled", "false").lower() == "true"
            key1_active = row.get("access_key_1_active", "false").lower() == "true"
            key2_active = row.get("access_key_2_active", "false").lower() == "true"

            issues = []
            if has_password and not mfa:
                issues.append("console_access_without_mfa")
            if user == "<root_account>" and (key1_active or key2_active):
                issues.append("root_access_keys_active")

            severity = "info"
            obs_type = "inventory"
            if "root_access_keys_active" in issues:
                severity = "critical"
                obs_type = "misconfiguration"
            elif "console_access_without_mfa" in issues:
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"IAM user: {user}" + (f" — {', '.join(issues)}" if issues else ""),
                    detail={
                        "user": user,
                        "mfa_active": mfa,
                        "password_enabled": has_password,
                        "access_key_1_active": key1_active,
                        "access_key_2_active": key2_active,
                        "issues": issues,
                    },
                    resource_id=f"arn:aws:iam::user/{user}"
                    if user != "<root_account>"
                    else "arn:aws:iam::root",
                    resource_type="iam_user",
                    resource_name=user,
                    severity=severity,
                )
            )

        return findings

    def _normalize_iam_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        users = raw.raw_data.get("response", {}).get("Users", [])
        for user in users:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"IAM user: {user.get('UserName', 'unknown')}",
                    detail=user,
                    resource_id=user.get("Arn", ""),
                    resource_type="iam_user",
                    resource_name=user.get("UserName", ""),
                    severity="info",
                )
            )
        return findings

    def _normalize_password_policy(self, raw: RawEventData) -> list[FindingData]:
        response = raw.raw_data.get("response", {})
        policy = response.get("PasswordPolicy", response)
        issues = []
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("no_uppercase_required")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("no_lowercase_required")
        if not policy.get("RequireSymbols", False):
            issues.append("no_symbols_required")
        if not policy.get("RequireNumbers", False):
            issues.append("no_numbers_required")
        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append("min_length_under_14")
        if not policy.get("MaxPasswordAge", 0):
            issues.append("no_password_expiration")

        return [
            FindingData(
                **self._base(raw),
                observation_type="misconfiguration" if issues else "inventory",
                title="IAM password policy"
                + (f" — {len(issues)} issues" if issues else " — compliant"),
                detail={"policy": policy, "issues": issues},
                resource_id="arn:aws:iam::account-password-policy",
                resource_type="iam_password_policy",
                resource_name="account-password-policy",
                severity="medium" if issues else "info",
            )
        ]

    def _normalize_account_summary(self, raw: RawEventData) -> list[FindingData]:
        summary = raw.raw_data.get("response", {}).get("SummaryMap", {})
        root_keys = summary.get("AccountAccessKeysPresent", 0)
        mfa_enabled = summary.get("AccountMFAEnabled", 0)
        issues = []
        if root_keys > 0:
            issues.append("root_access_keys_present")
        if not mfa_enabled:
            issues.append("root_mfa_not_enabled")

        severity = "info"
        if "root_access_keys_present" in issues:
            severity = "critical"
        elif "root_mfa_not_enabled" in issues:
            severity = "critical"

        return [
            FindingData(
                **self._base(raw),
                observation_type="misconfiguration" if issues else "inventory",
                title="AWS account summary" + (f" — {', '.join(issues)}" if issues else ""),
                detail={"summary": summary, "issues": issues},
                resource_id="arn:aws:iam::root",
                resource_type="iam_account",
                resource_name="account",
                severity=severity,
            )
        ]

    # -- EC2 / Networking --

    def _normalize_security_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        sgs = raw.raw_data.get("response", {}).get("SecurityGroups", [])
        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379}

        for sg in sgs:
            issues = []
            for rule in sg.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        port = rule.get("FromPort", 0)
                        if port in sensitive_ports or rule.get("IpProtocol") == "-1":
                            issues.append(f"open_to_world_port_{port}")

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type=obs_type,
                    title=f"Security group {sg.get('GroupId', '?')}"
                    + (f" — {len(issues)} open ports" if issues else ""),
                    detail={"security_group": sg, "issues": issues},
                    resource_id=sg.get("GroupId", ""),
                    resource_type="ec2_security_group",
                    resource_name=sg.get("GroupName", ""),
                    severity=severity,
                )
            )
        return findings

    def _normalize_network_acls(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        acls = raw.raw_data.get("response", {}).get("NetworkAcls", [])
        for acl in acls:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Network ACL {acl.get('NetworkAclId', '?')}",
                    detail=acl,
                    resource_id=acl.get("NetworkAclId", ""),
                    resource_type="ec2_network_acl",
                    resource_name=acl.get("NetworkAclId", ""),
                    severity="info",
                )
            )
        return findings

    # -- CloudTrail --

    def _normalize_cloudtrail(self, raw: RawEventData) -> list[FindingData]:
        trails = raw.raw_data.get("response", {}).get("trailList", [])
        if not trails:
            return [
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="CloudTrail — no trails configured",
                    detail={"trails": [], "issues": ["no_trails"]},
                    resource_id="cloudtrail",
                    resource_type="cloudtrail",
                    resource_name="cloudtrail",
                    severity="critical",
                )
            ]

        findings = []
        for trail in trails:
            issues = []
            if not trail.get("IsMultiRegionTrail", False):
                issues.append("not_multi_region")
            if not trail.get("LogFileValidationEnabled", False):
                issues.append("no_log_validation")

            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration" if issues else "inventory",
                    title=f"CloudTrail: {trail.get('Name', '?')}"
                    + (f" — {', '.join(issues)}" if issues else ""),
                    detail={"trail": trail, "issues": issues},
                    resource_id=trail.get("TrailARN", ""),
                    resource_type="cloudtrail",
                    resource_name=trail.get("Name", ""),
                    severity="medium" if issues else "info",
                )
            )
        return findings

    # -- GuardDuty --

    def _normalize_guardduty(self, raw: RawEventData) -> list[FindingData]:
        detectors = raw.raw_data.get("response", {}).get("DetectorIds", [])
        if not detectors:
            return [
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="GuardDuty — not enabled",
                    detail={"detectors": [], "issues": ["not_enabled"]},
                    resource_id="guardduty",
                    resource_type="guardduty",
                    resource_name="guardduty",
                    severity="high",
                )
            ]
        return [
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title=f"GuardDuty — {len(detectors)} detector(s) active",
                detail={"detectors": detectors},
                resource_id="guardduty",
                resource_type="guardduty",
                resource_name="guardduty",
                severity="info",
            )
        ]

    # -- SecurityHub --

    def _normalize_securityhub(self, raw: RawEventData) -> list[FindingData]:
        hub = raw.raw_data.get("response", {})
        if not hub.get("HubArn"):
            return [
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="SecurityHub — not enabled",
                    detail={"hub": hub, "issues": ["not_enabled"]},
                    resource_id="securityhub",
                    resource_type="securityhub",
                    resource_name="securityhub",
                    severity="high",
                )
            ]
        return [
            FindingData(
                **self._base(raw),
                observation_type="inventory",
                title="SecurityHub — enabled",
                detail={"hub": hub},
                resource_id=hub.get("HubArn", ""),
                resource_type="securityhub",
                resource_name="securityhub",
                severity="info",
            )
        ]

    # -- S3 --

    def _normalize_s3_buckets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        buckets = raw.raw_data.get("response", {}).get("Buckets", [])
        for bucket in buckets:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"S3 bucket: {bucket.get('Name', '?')}",
                    detail=bucket,
                    resource_id=f"arn:aws:s3:::{bucket.get('Name', '')}",
                    resource_type="s3_bucket",
                    resource_name=bucket.get("Name", ""),
                    severity="info",
                )
            )
        return findings

    # -- Config --

    def _normalize_config_recorders(self, raw: RawEventData) -> list[FindingData]:
        recorders = raw.raw_data.get("response", {}).get("ConfigurationRecorders", [])
        if not recorders:
            return [
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="AWS Config — no recorders configured",
                    detail={"recorders": [], "issues": ["not_enabled"]},
                    resource_id="config",
                    resource_type="aws_config",
                    resource_name="config",
                    severity="high",
                )
            ]
        findings = []
        for rec in recorders:
            all_supported = rec.get("recordingGroup", {}).get("allSupported", False)
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory" if all_supported else "misconfiguration",
                    title=f"AWS Config recorder: {rec.get('name', '?')}"
                    + ("" if all_supported else " — not recording all resources"),
                    detail={
                        "recorder": rec,
                        "issues": [] if all_supported else ["not_all_supported"],
                    },
                    resource_id=f"config:{rec.get('name', '')}",
                    resource_type="aws_config",
                    resource_name=rec.get("name", ""),
                    severity="info" if all_supported else "medium",
                )
            )
        return findings

    # -- Config Compliance --

    def _normalize_config_compliance(self, raw: RawEventData) -> list[FindingData]:
        """Normalize AWS Config compliance evaluation results."""
        findings = []
        results = raw.raw_data.get("response", {}).get("EvaluationResults", [])
        for result in results:
            resource_id = (
                result.get("EvaluationResultIdentifier", {})
                .get("EvaluationResultQualifier", {})
                .get("ResourceId", "")
            )
            resource_type = (
                result.get("EvaluationResultIdentifier", {})
                .get("EvaluationResultQualifier", {})
                .get("ResourceType", "")
            )
            compliance = result.get("ComplianceType", "")
            rule_name = (
                result.get("EvaluationResultIdentifier", {})
                .get("EvaluationResultQualifier", {})
                .get("ConfigRuleName", "")
            )

            is_compliant = compliance == "COMPLIANT"
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory" if is_compliant else "misconfiguration",
                    title=f"Config rule {rule_name}: {compliance}",
                    detail=result,
                    resource_id=resource_id,
                    resource_type=resource_type,
                    resource_name=resource_id,
                    severity="info" if is_compliant else "medium",
                )
            )
        return findings

    # -- IAM Policies --

    def _normalize_iam_policies(self, raw: RawEventData) -> list[FindingData]:
        """Normalize IAM policy listing."""
        findings = []
        policies = raw.raw_data.get("response", {}).get("Policies", [])
        for policy in policies:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"IAM policy: {policy.get('PolicyName', '?')}",
                    detail=policy,
                    resource_id=policy.get("Arn", ""),
                    resource_type="iam_policy",
                    resource_name=policy.get("PolicyName", ""),
                    severity="info",
                )
            )
        return findings

    # -- EC2 VPCs --

    def _normalize_ec2_vpcs(self, raw: RawEventData) -> list[FindingData]:
        """Normalize VPC inventory."""
        findings = []
        vpcs = raw.raw_data.get("response", {}).get("Vpcs", [])
        for vpc in vpcs:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"VPC: {vpc.get('VpcId', '?')}",
                    detail=vpc,
                    resource_id=vpc.get("VpcId", ""),
                    resource_type="ec2_vpc",
                    resource_name=vpc.get("VpcId", ""),
                    severity="info",
                )
            )
        return findings

    # -- EC2 Flow Logs --

    def _normalize_ec2_flow_logs(self, raw: RawEventData) -> list[FindingData]:
        """Normalize VPC flow log configuration."""
        flow_logs = raw.raw_data.get("response", {}).get("FlowLogs", [])
        if not flow_logs:
            return [
                FindingData(
                    **self._base(raw),
                    observation_type="misconfiguration",
                    title="VPC flow logs - none configured",
                    detail={"flow_logs": [], "issues": ["no_flow_logs"]},
                    resource_id="vpc-flow-logs",
                    resource_type="ec2_flow_log",
                    resource_name="flow-logs",
                    severity="medium",
                )
            ]
        findings = []
        for fl in flow_logs:
            findings.append(
                FindingData(
                    **self._base(raw),
                    observation_type="inventory",
                    title=f"Flow log: {fl.get('FlowLogId', '?')}",
                    detail=fl,
                    resource_id=fl.get("FlowLogId", ""),
                    resource_type="ec2_flow_log",
                    resource_name=fl.get("FlowLogId", ""),
                    severity="info",
                )
            )
        return findings

    # -- CloudTrail Status --

    def _normalize_cloudtrail_status(self, raw: RawEventData) -> list[FindingData]:
        """Normalize CloudTrail trail status (get_trail_status response)."""
        status = raw.raw_data.get("response", {})
        is_logging = status.get("IsLogging", False)
        issues = []
        if not is_logging:
            issues.append("logging_disabled")

        return [
            FindingData(
                **self._base(raw),
                observation_type="misconfiguration" if issues else "inventory",
                title="CloudTrail status" + (" - logging disabled" if issues else " - active"),
                detail={"status": status, "issues": issues},
                resource_id=raw.raw_data.get("trail_arn", "cloudtrail"),
                resource_type="cloudtrail",
                resource_name="cloudtrail-status",
                severity="high" if issues else "info",
            )
        ]


# Register
registry.register(AWSNormalizer())
