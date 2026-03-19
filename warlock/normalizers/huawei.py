"""Huawei Cloud normalizer — transforms raw Huawei API responses into Findings.

Each event_type gets a handler that knows the shape of that specific API
response and extracts structured observations from it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.connectors.base import RawEventData, SourceType
from warlock.normalizers.base import BaseNormalizer, FindingData, registry


class HuaweiNormalizer(BaseNormalizer):
    """Dispatches to event_type-specific handlers."""

    HANDLERS: dict[str, str] = {
        "huawei_hss_events": "_normalize_hss_events",
        "huawei_iam_users": "_normalize_iam_users",
        "huawei_cts_events": "_normalize_cts_events",
        "huawei_security_groups": "_normalize_security_groups",
        "huawei_kms_keys": "_normalize_kms_keys",
        "huawei_obs_buckets": "_normalize_obs_buckets",
    }

    def can_handle(self, raw_event: RawEventData) -> bool:
        return raw_event.source == "huawei" and raw_event.event_type in self.HANDLERS

    def normalize(self, raw_event: RawEventData) -> list[FindingData]:
        handler_name = self.HANDLERS[raw_event.event_type]
        handler = getattr(self, handler_name)
        return handler(raw_event)

    def _base(self, raw: RawEventData) -> dict:
        """Common fields for all Huawei Cloud findings."""
        return {
            "raw_event_id": raw.id,
            "source": "huawei",
            "source_type": SourceType.CLOUD,
            "provider": "huawei",
            "account_id": raw.raw_data.get("project_id", ""),
            "region": raw.raw_data.get("region", ""),
            "observed_at": raw.observed_at,
        }

    # -- HSS Events (Host Security Service) --

    def _normalize_hss_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        events = response.get("events", [])

        severity_map = {
            "Critical": "critical",
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Prompt": "info",
        }

        for event in events:
            event_name = event.get("event_name", "unknown")
            event_type = event.get("event_type", "")
            severity_raw = event.get("severity", "Medium")
            mapped_severity = severity_map.get(severity_raw, "medium")
            host_name = event.get("host_name", "")
            host_id = event.get("host_id", "")

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"HSS alert: {event_name}",
                detail={
                    "event_name": event_name,
                    "event_type": event_type,
                    "severity": severity_raw,
                    "host_name": host_name,
                    "host_id": host_id,
                    "occur_time": event.get("occur_time", ""),
                    "description": event.get("description", ""),
                    "handle_status": event.get("handle_status", ""),
                    "operate_detail": event.get("operate_detail", {}),
                },
                resource_id=host_id,
                resource_type="ecs_instance",
                resource_name=host_name,
                severity=mapped_severity,
            ))

        return findings

    # -- IAM Users --

    def _normalize_iam_users(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        users = response.get("users", [])
        now = datetime.now(timezone.utc)

        for user in users:
            user_name = user.get("name", "unknown")
            user_id = user.get("id", "")
            enabled = user.get("enabled", True)
            mfa_enabled = user.get("mfa_device", None) is not None
            pwd_status = user.get("pwd_status", None)
            last_login = user.get("last_project_id", "")  # proxy for activity

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Flag users without MFA
            if not mfa_enabled and enabled:
                issues.append("mfa_not_enabled")
                severity = "high"
                obs_type = "misconfiguration"

            # Flag disabled users still present
            if not enabled:
                issues.append("user_disabled")

            # Check password status for staleness
            pwd_expires_at = user.get("pwd_strength", "")
            last_login_time = user.get("last_login_time", "")
            if last_login_time:
                try:
                    last_dt = datetime.fromisoformat(
                        last_login_time.replace("Z", "+00:00")
                    )
                    days_inactive = (now - last_dt).days
                    if days_inactive > 90:
                        issues.append(f"stale_user_{days_inactive}_days")
                        if severity == "info":
                            severity = "medium"
                            obs_type = "misconfiguration"
                except (ValueError, TypeError):
                    pass

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"IAM user: {user_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "user_name": user_name,
                    "user_id": user_id,
                    "enabled": enabled,
                    "mfa_enabled": mfa_enabled,
                    "last_login_time": last_login_time,
                    "pwd_status": pwd_status,
                    "issues": issues,
                },
                resource_id=user_id,
                resource_type="iam_user",
                resource_name=user_name,
                severity=severity,
            ))

        return findings

    # -- CTS Events (Cloud Trace Service) --

    def _normalize_cts_events(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        traces = response.get("traces", [])

        for trace in traces:
            trace_status = trace.get("trace_status", "normal")

            # Only emit findings for error/warning traces
            if trace_status == "normal":
                continue

            trace_name = trace.get("trace_name", "unknown")
            service_type = trace.get("service_type", "")
            resource_type = trace.get("resource_type", "")
            resource_name = trace.get("resource_name", "")
            resource_id = trace.get("resource_id", "")
            user_info = trace.get("user", {})

            severity = "medium"
            if trace_status == "error":
                severity = "high"

            findings.append(FindingData(
                **self._base(raw),
                observation_type="alert",
                title=f"CTS trace: {trace_name} — {trace_status}",
                detail={
                    "trace_name": trace_name,
                    "trace_status": trace_status,
                    "service_type": service_type,
                    "resource_type": resource_type,
                    "resource_name": resource_name,
                    "resource_id": resource_id,
                    "user": user_info,
                    "trace_id": trace.get("trace_id", ""),
                    "record_time": trace.get("record_time", ""),
                    "request": trace.get("request", {}),
                    "response_code": trace.get("code", ""),
                },
                resource_id=resource_id or trace.get("trace_id", ""),
                resource_type=resource_type or service_type or "huawei_resource",
                resource_name=resource_name,
                severity=severity,
            ))

        return findings

    # -- VPC Security Groups --

    def _normalize_security_groups(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        security_groups = response.get("security_groups", [])
        sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 8080, 8443}

        for sg in security_groups:
            sg_name = sg.get("name", "unknown")
            sg_id = sg.get("id", "")
            rules = sg.get("security_group_rules", [])
            issues = []

            for rule in rules:
                direction = rule.get("direction", "")
                if direction != "ingress":
                    continue

                remote_ip = rule.get("remote_ip_prefix", "")
                if remote_ip not in ("0.0.0.0/0", "::/0"):
                    continue

                protocol = rule.get("protocol", "")
                port_min = rule.get("port_range_min")
                port_max = rule.get("port_range_max")

                # All traffic open
                if protocol is None or protocol == "":
                    issues.append("all_traffic_open_to_internet")
                    continue

                # All ports for this protocol
                if port_min is None and port_max is None:
                    issues.append(f"all_{protocol}_ports_open_to_internet")
                    continue

                # Specific port range
                if port_min is not None and port_max is not None:
                    try:
                        pmin = int(port_min)
                        pmax = int(port_max)
                        for p in sensitive_ports:
                            if pmin <= p <= pmax:
                                issues.append(
                                    f"open_to_internet_{protocol}_port_{p}"
                                )
                    except (ValueError, TypeError):
                        pass

            severity = "info"
            obs_type = "inventory"
            if issues:
                severity = "high"
                obs_type = "misconfiguration"
                if "all_traffic_open_to_internet" in issues:
                    severity = "critical"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"Security group: {sg_name}" + (
                    f" — {len(issues)} open rules" if issues else ""
                ),
                detail={
                    "security_group": sg,
                    "issues": issues,
                },
                resource_id=sg_id,
                resource_type="vpc_security_group",
                resource_name=sg_name,
                severity=severity,
            ))

        return findings

    # -- KMS Keys --

    def _normalize_kms_keys(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        keys = response.get("keys", [])
        key_details = response.get("key_details", keys)

        for key in key_details:
            key_id = key.get("key_id", "")
            key_alias = key.get("key_alias", key_id)
            key_state = key.get("key_state", "")

            issues = []
            severity = "info"
            obs_type = "inventory"

            # Key state checks
            # 2 = enabled, 3 = disabled, 4 = pending deletion, 5 = pending import
            state_names = {
                "1": "creating",
                "2": "enabled",
                "3": "disabled",
                "4": "pending_deletion",
                "5": "pending_import",
            }
            state_str = state_names.get(str(key_state), str(key_state))

            if str(key_state) == "3":
                issues.append("key_disabled")
                severity = "medium"
                obs_type = "misconfiguration"
            elif str(key_state) == "4":
                issues.append("key_pending_deletion")
                severity = "high"
                obs_type = "alert"

            # Check rotation interval
            rotation_interval = key.get("key_rotation_interval", 0)
            rotation_enabled = key.get("rotation_enabled", False)
            if not rotation_enabled and str(key_state) == "2":
                issues.append("rotation_not_enabled")
                if severity == "info":
                    severity = "medium"
                    obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"KMS key: {key_alias}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "key_id": key_id,
                    "key_alias": key_alias,
                    "key_state": state_str,
                    "key_type": key.get("key_type", ""),
                    "creation_date": key.get("creation_date", ""),
                    "rotation_enabled": rotation_enabled,
                    "rotation_interval": rotation_interval,
                    "issues": issues,
                },
                resource_id=key_id,
                resource_type="kms_key",
                resource_name=key_alias,
                severity=severity,
            ))

        return findings

    # -- OBS Buckets --

    def _normalize_obs_buckets(self, raw: RawEventData) -> list[FindingData]:
        findings = []
        response = raw.raw_data.get("response", {})
        buckets = response.get("buckets", [])

        for bucket in buckets:
            bucket_name = bucket.get("name", "unknown")
            issues = []
            severity = "info"
            obs_type = "inventory"

            # Check ACL for public access
            acl = bucket.get("acl", {})
            grants = acl.get("grants", [])
            for grant in grants:
                grantee = grant.get("grantee", {})
                grantee_uri = grantee.get("uri", "")
                grantee_type = grantee.get("type", "")
                permission = grant.get("permission", "")

                # AllUsers or AuthenticatedUsers = public
                if "AllUsers" in grantee_uri or "Everyone" in grantee_uri:
                    issues.append(f"public_acl_{permission.lower()}")
                    severity = "critical"
                    obs_type = "misconfiguration"
                elif "AuthenticatedUsers" in grantee_uri:
                    issues.append(f"authenticated_users_acl_{permission.lower()}")
                    severity = "high"
                    obs_type = "misconfiguration"

            # Check bucket policy for public access if embedded
            policy = bucket.get("policy", {})
            if policy:
                statements = policy.get("Statement", [])
                for stmt in statements:
                    principal = stmt.get("Principal", {})
                    if principal == "*" or principal == {"AWS": "*"}:
                        effect = stmt.get("Effect", "")
                        if effect == "Allow":
                            issues.append("public_bucket_policy")
                            severity = "critical"
                            obs_type = "misconfiguration"

            # Check logging
            logging_enabled = bucket.get("logging_enabled", None)
            if logging_enabled is False:
                issues.append("logging_disabled")
                if severity == "info":
                    severity = "low"
                    obs_type = "misconfiguration"

            # Check versioning
            versioning = bucket.get("versioning", "")
            if versioning not in ("Enabled",):
                issues.append("versioning_not_enabled")
                if severity == "info":
                    severity = "low"
                    obs_type = "misconfiguration"

            findings.append(FindingData(
                **self._base(raw),
                observation_type=obs_type,
                title=f"OBS bucket: {bucket_name}" + (
                    f" — {', '.join(issues)}" if issues else ""
                ),
                detail={
                    "bucket_name": bucket_name,
                    "location": bucket.get("location", ""),
                    "creation_date": bucket.get("creation_date", ""),
                    "acl": acl,
                    "versioning": versioning,
                    "issues": issues,
                },
                resource_id=f"obs://{bucket_name}",
                resource_type="obs_bucket",
                resource_name=bucket_name,
                severity=severity,
            ))

        return findings


# Register
registry.register(HuaweiNormalizer())
