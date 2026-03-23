"""Assertion library for compliance checks.

Registers deterministic assertion functions with the singleton engine.
Each assertion takes (detail: dict, raw_data: dict) -> (bool, list[str])
and is bound to relevant NIST 800-53 controls.
"""

from __future__ import annotations

from datetime import datetime, timezone

from warlock.utils import ensure_aware
from typing import Any

from warlock.assessors.engine import engine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(d: dict, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dict keys."""
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def _days_since(date_str: str | None) -> int | None:
    """Return days since a date string, or None if unparseable."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(date_str, fmt)
            dt = ensure_aware(dt)
            return (datetime.now(timezone.utc) - dt).days
        except (ValueError, TypeError):
            continue
    return None


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------


@engine.assertion("mfa_enabled")
def mfa_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that IAM/IdP users have MFA enabled.

    Works across AWS IAM credential reports, Okta users/factors, and Entra ID.
    """
    reasons: list[str] = []

    # AWS IAM credential report shape
    mfa_active = detail.get("mfa_active")
    password_enabled = detail.get("password_enabled")
    if mfa_active is not None:
        if password_enabled and not mfa_active:
            reasons.append(f"User {detail.get('user', 'unknown')} has console access without MFA")
        if not reasons:
            return True, []
        return False, reasons

    # Okta user shape — check enrolled factors
    factors = detail.get("factors", detail.get("enrolled_factors", []))
    if isinstance(factors, list) and len(factors) > 0:
        return True, []

    # Okta user status check
    okta_status = detail.get("status")
    if okta_status is not None:
        mfa_factors = detail.get("mfa_factors", [])
        if isinstance(mfa_factors, list) and len(mfa_factors) > 0:
            return True, []
        credentials = detail.get("credentials", {})
        if isinstance(credentials, dict) and credentials.get("provider", {}).get("type") == "OKTA":
            reasons.append(
                f"Okta user {detail.get('login', detail.get('email', 'unknown'))} — no MFA factors enrolled"
            )
            return False, reasons

    # Entra ID shape
    auth_methods = detail.get("authenticationMethods", detail.get("authentication_methods", []))
    if isinstance(auth_methods, list) and len(auth_methods) > 1:
        return True, []
    strong_auth = detail.get("strongAuthenticationDetail", detail.get("strong_authentication", {}))
    if isinstance(strong_auth, dict) and strong_auth.get("methods"):
        return True, []

    # Entra conditional access — mfa required
    grant_controls = _get(detail, "grantControls", "builtInControls", default=[])
    if isinstance(grant_controls, list) and "mfa" in grant_controls:
        return True, []

    # Generic fallback: check for mfa_enabled field
    if detail.get("mfa_enabled") is True:
        return True, []

    # If we have identity data but no MFA evidence, flag it
    user_id = (
        detail.get("user")
        or detail.get("login")
        or detail.get("userPrincipalName")
        or detail.get("displayName")
    )
    if user_id:
        reasons.append(f"User {user_id} — no MFA evidence found")
        return False, reasons

    # Insufficient data to determine — fail closed
    return False, ["Insufficient data to determine MFA status"]


@engine.assertion("no_root_access_keys")
def no_root_access_keys(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that root/admin account has no active access keys."""
    reasons: list[str] = []

    # AWS credential report shape
    user = detail.get("user", "")
    if user == "<root_account>":
        if detail.get("access_key_1_active") or detail.get("access_key_2_active"):
            reasons.append("Root account has active access keys")
            return False, reasons
        return True, []

    # AWS account summary shape
    summary = detail.get("summary", {})
    if isinstance(summary, dict):
        root_keys = summary.get("AccountAccessKeysPresent", 0)
        if root_keys > 0:
            reasons.append(f"Root account has {root_keys} active access key(s)")
            return False, reasons
        if "AccountAccessKeysPresent" in summary:
            return True, []

    # Check issues list
    issues = detail.get("issues", [])
    if isinstance(issues, list):
        if "root_access_keys_active" in issues or "root_access_keys_present" in issues:
            reasons.append("Root account has active access keys")
            return False, reasons

    # If the finding is clearly about a non-root user (has a user field that
    # is not root-like), the assertion is not applicable — pass through.
    if user and user != "<root_account>" and "root" not in user.lower():
        return True, []

    # Looks like it should have root key data but doesn't — fail closed
    return False, ["No root access key data available"]


@engine.assertion("cloudtrail_enabled")
def cloudtrail_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that CloudTrail/audit logging is enabled and multi-region."""
    reasons: list[str] = []

    # Check for no-trails issue
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_trails" in issues:
        reasons.append("No CloudTrail trails configured")
        return False, reasons

    trail = detail.get("trail", {})
    if isinstance(trail, dict):
        if not trail.get("IsMultiRegionTrail", False):
            reasons.append("CloudTrail is not multi-region")
        if not trail.get("LogFileValidationEnabled", False):
            reasons.append("Log file validation is not enabled")
        if reasons:
            return False, reasons
        return True, []

    # GCP audit logs
    if detail.get("logName") or detail.get("log_name"):
        return True, []

    # Azure activity log
    if detail.get("operationName") or detail.get("operation_name"):
        return True, []

    # Fallback issues check
    if isinstance(issues, list):
        if "not_multi_region" in issues:
            reasons.append("CloudTrail is not multi-region")
        if "no_log_validation" in issues:
            reasons.append("Log file validation is not enabled")
        if reasons:
            return False, reasons

    return True, []


@engine.assertion("guardduty_enabled")
def guardduty_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that threat detection (GuardDuty/SCC/Defender) is active."""
    reasons: list[str] = []

    issues = detail.get("issues", [])
    if isinstance(issues, list) and "not_enabled" in issues:
        reasons.append("Threat detection service is not enabled")
        return False, reasons

    detectors = detail.get("detectors", [])
    if isinstance(detectors, list) and len(detectors) > 0:
        return True, []

    # SCC findings or Defender alerts indicate active detection
    if detail.get("findings") or detail.get("alerts"):
        return True, []

    # Hub or detector ARN present means enabled
    if detail.get("HubArn") or detail.get("DetectorId"):
        return True, []

    return True, []


@engine.assertion("securityhub_enabled")
def securityhub_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that security hub/CSPM is active."""
    reasons: list[str] = []

    issues = detail.get("issues", [])
    if isinstance(issues, list) and "not_enabled" in issues:
        reasons.append("SecurityHub is not enabled")
        return False, reasons

    hub = detail.get("hub", {})
    if isinstance(hub, dict) and hub.get("HubArn"):
        return True, []

    if detail.get("HubArn"):
        return True, []

    return True, []


@engine.assertion("no_open_security_groups")
def no_open_security_groups(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that no security group allows unrestricted ingress on sensitive ports."""
    reasons: list[str] = []

    issues = detail.get("issues", [])
    if isinstance(issues, list):
        open_ports = [i for i in issues if i.startswith("open_to_world")]
        if open_ports:
            sg_id = _get(detail, "security_group", "GroupId", default="unknown")
            reasons.append(
                f"Security group {sg_id} has unrestricted ingress: {', '.join(open_ports)}"
            )
            return False, reasons

    # GCP firewall rule shape
    sg = detail.get("security_group", detail)
    ip_permissions = sg.get("IpPermissions", [])
    sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379}
    for rule in ip_permissions:
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                port = rule.get("FromPort", 0)
                if port in sensitive_ports or rule.get("IpProtocol") == "-1":
                    reasons.append(f"Open to world on port {port}")

    # GCP firewall check
    source_ranges = detail.get("sourceRanges", [])
    if isinstance(source_ranges, list) and "0.0.0.0/0" in source_ranges:
        allowed = detail.get("allowed", [])
        for a in allowed if isinstance(allowed, list) else []:
            ports = a.get("ports", [])
            if not ports:
                reasons.append("GCP firewall rule allows all ports from 0.0.0.0/0")
            for p in ports if isinstance(ports, list) else []:
                reasons.append(f"GCP firewall rule allows port {p} from 0.0.0.0/0")

    # Azure NSG check
    nsg_rules = detail.get("securityRules", detail.get("security_rules", []))
    if isinstance(nsg_rules, list):
        for rule in nsg_rules:
            props = rule.get("properties", rule)
            if (
                props.get("access") == "Allow"
                and props.get("direction") == "Inbound"
                and props.get("sourceAddressPrefix") in ("*", "0.0.0.0/0")
            ):
                reasons.append(
                    f"Azure NSG rule {props.get('name', '?')} allows unrestricted inbound"
                )

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("encryption_at_rest")
def encryption_at_rest(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that storage resources have encryption at rest enabled."""
    reasons: list[str] = []

    # S3 bucket
    encryption = detail.get("ServerSideEncryptionConfiguration") or detail.get("encryption")
    if detail.get("Name") and not encryption:
        # Check in raw_data for encryption info
        bucket_encryption = _get(raw_data, "encryption", default=None)
        if bucket_encryption is None:
            reasons.append(
                f"S3 bucket {detail.get('Name', '?')} — no encryption configuration found"
            )

    # Azure storage account
    azure_encryption = detail.get("encryption", {})
    if isinstance(azure_encryption, dict):
        services = azure_encryption.get("services", {})
        if isinstance(services, dict):
            for svc_name, svc_config in services.items():
                if isinstance(svc_config, dict) and not svc_config.get("enabled", True):
                    reasons.append(f"Azure storage encryption not enabled for {svc_name}")

    # GCS bucket
    detail.get("defaultObjectAcl", [])
    if detail.get("kind") == "storage#bucket":
        bucket_encryption = detail.get("encryption", {})
        if not isinstance(bucket_encryption, dict) or not bucket_encryption.get(
            "defaultKmsKeyName"
        ):
            # GCS uses Google-managed keys by default, which is acceptable
            pass

    # Azure Key Vault
    if detail.get("vaultUri") or detail.get("vault_uri"):
        hsm = detail.get("sku", {}).get("name", "")
        if hsm and "premium" not in hsm.lower():
            # Standard tier is still encrypted, not a failure
            pass

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("password_policy_compliant")
def password_policy_compliant(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that password policy meets compliance requirements."""
    reasons: list[str] = []

    # AWS password policy shape
    policy = detail.get("policy", detail)
    issues = detail.get("issues", [])

    if isinstance(issues, list) and issues:
        for issue in issues:
            if issue == "min_length_under_14":
                reasons.append("Minimum password length is under 14 characters")
            elif issue == "no_uppercase_required":
                reasons.append("Uppercase characters not required")
            elif issue == "no_lowercase_required":
                reasons.append("Lowercase characters not required")
            elif issue == "no_symbols_required":
                reasons.append("Symbols not required")
            elif issue == "no_numbers_required":
                reasons.append("Numbers not required")
            elif issue == "no_password_expiration":
                reasons.append("Password expiration not configured")
            else:
                reasons.append(f"Password policy issue: {issue}")
        return False, reasons

    # Direct policy object check
    if isinstance(policy, dict) and "MinimumPasswordLength" in policy:
        if policy.get("MinimumPasswordLength", 0) < 14:
            reasons.append("Minimum password length is under 14 characters")
        if not policy.get("RequireUppercaseCharacters", False):
            reasons.append("Uppercase characters not required")
        if not policy.get("RequireLowercaseCharacters", False):
            reasons.append("Lowercase characters not required")
        if not policy.get("RequireSymbols", False):
            reasons.append("Symbols not required")
        if not policy.get("RequireNumbers", False):
            reasons.append("Numbers not required")
        if reasons:
            return False, reasons

    # CyberArk password compliance shape
    compliant = detail.get("compliant") or detail.get("is_compliant")
    if compliant is False:
        reasons.append("CyberArk password compliance check failed")
        return False, reasons

    return True, []


@engine.assertion("config_recorder_enabled")
def config_recorder_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that AWS Config or equivalent configuration recorder is active."""
    reasons: list[str] = []

    issues = detail.get("issues", [])
    if isinstance(issues, list) and "not_enabled" in issues:
        reasons.append("Configuration recorder is not enabled")
        return False, reasons

    recorder = detail.get("recorder", {})
    if isinstance(recorder, dict):
        recording_group = recorder.get("recordingGroup", {})
        if isinstance(recording_group, dict) and not recording_group.get("allSupported", False):
            reasons.append("Configuration recorder is not recording all resource types")
            return False, reasons

    if isinstance(issues, list) and "not_all_supported" in issues:
        reasons.append("Configuration recorder is not recording all resource types")
        return False, reasons

    return True, []


@engine.assertion("no_public_storage")
def no_public_storage(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that storage (S3/GCS/Azure Storage) is not publicly accessible."""
    reasons: list[str] = []

    # S3 — check ACL and policy
    acl = detail.get("Grants", detail.get("grants", []))
    if isinstance(acl, list):
        for grant in acl:
            grantee = grant.get("Grantee", grant.get("grantee", {}))
            if isinstance(grantee, dict):
                uri = grantee.get("URI", grantee.get("uri", ""))
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    reasons.append(f"Storage has public ACL grant: {uri}")

    # S3 public access block
    public_access = detail.get(
        "PublicAccessBlockConfiguration", detail.get("public_access_block", {})
    )
    if isinstance(public_access, dict) and public_access:
        if not public_access.get("BlockPublicAcls", True):
            reasons.append("BlockPublicAcls is not enabled")
        if not public_access.get("BlockPublicPolicy", True):
            reasons.append("BlockPublicPolicy is not enabled")

    # GCS — check IAM
    iam_config = detail.get("iamConfiguration", {})
    if isinstance(iam_config, dict):
        if not iam_config.get("uniformBucketLevelAccess", {}).get("enabled", True):
            reasons.append("GCS bucket does not have uniform bucket-level access")

    # Azure storage — check public access
    allow_blob_public = detail.get("allowBlobPublicAccess", detail.get("allow_blob_public_access"))
    if allow_blob_public is True:
        reasons.append("Azure storage account allows public blob access")

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("endpoint_protection_active")
def endpoint_protection_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that EDR/endpoint protection agents are active (CrowdStrike, Defender, SentinelOne)."""
    reasons: list[str] = []

    # CrowdStrike device shape
    status = detail.get("status") or detail.get("agent_status") or detail.get("sensor_status")
    hostname = (
        detail.get("hostname")
        or detail.get("computerDnsName")
        or detail.get("computer_name")
        or "unknown"
    )

    if status is not None:
        status_lower = str(status).lower()
        if status_lower in ("offline", "inactive", "disconnected", "decommissioned"):
            reasons.append(f"Endpoint {hostname} — agent status: {status}")
            return False, reasons
        if status_lower in ("online", "active", "connected", "normal"):
            return True, []

    # CrowdStrike device detail
    last_seen = detail.get("last_seen") or detail.get("lastSeen") or detail.get("last_active")
    if last_seen:
        days = _days_since(str(last_seen))
        if days is not None and days > 7:
            reasons.append(f"Endpoint {hostname} — last seen {days} days ago")
            return False, reasons

    # SentinelOne agent shape
    is_active = detail.get("isActive", detail.get("is_active"))
    if is_active is False:
        reasons.append(f"Endpoint {hostname} — SentinelOne agent inactive")
        return False, reasons

    # Defender machine shape
    health_status = detail.get("healthStatus") or detail.get("health_status")
    if health_status is not None:
        if str(health_status).lower() in ("inactive", "impairedcommunication", "noscreenupdates"):
            reasons.append(f"Endpoint {hostname} — Defender health: {health_status}")
            return False, reasons

    # Fleet summary shape
    total = detail.get("total_devices") or detail.get("total_agents", 0)
    offline = detail.get("offline_devices") or detail.get("offline_agents", 0)
    if total and offline:
        pct = (offline / total) * 100
        if pct > 10:
            reasons.append(f"Fleet has {offline}/{total} ({pct:.0f}%) offline agents")
            return False, reasons

    return True, []


@engine.assertion("vulnerability_scan_current")
def vulnerability_scan_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that vulnerability scans are recent (within 30 days)."""
    reasons: list[str] = []

    # Tenable/Qualys shape
    last_scan = (
        detail.get("last_scan_date")
        or detail.get("lastScanned")
        or detail.get("last_assessed_at")
        or detail.get("last_scan")
        or _get(detail, "scan", "last_run", default=None)
    )
    if last_scan:
        days = _days_since(str(last_scan))
        if days is not None and days > 30:
            host = detail.get("hostname") or detail.get("host") or detail.get("ip") or "unknown"
            reasons.append(f"Host {host} — last scanned {days} days ago")
            return False, reasons
        if days is not None:
            return True, []

    # Wiz/Prisma vulnerability shape
    found_date = detail.get("firstDetected") or detail.get("found_date") or detail.get("createdAt")
    fixed_date = detail.get("resolvedAt") or detail.get("fixed_date")
    if found_date and not fixed_date:
        days = _days_since(str(found_date))
        if days is not None and days > 90:
            reasons.append(f"Vulnerability open for {days} days without remediation")
            return False, reasons

    # Scan summary
    scan_count = detail.get("scan_count") or detail.get("total_scans")
    if scan_count is not None and scan_count == 0:
        reasons.append("No vulnerability scans have been performed")
        return False, reasons

    return True, []


@engine.assertion("privileged_access_managed")
def privileged_access_managed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that privileged accounts are managed via PAM (CyberArk)."""
    reasons: list[str] = []

    # CyberArk account shape
    platform_id = detail.get("platformId") or detail.get("platform_id")
    safe_name = detail.get("safeName") or detail.get("safe_name")

    # Check if account is managed
    secret_mgmt = detail.get("secretManagement", detail.get("secret_management", {}))
    if isinstance(secret_mgmt, dict):
        auto_mgmt = secret_mgmt.get(
            "automaticManagementEnabled", secret_mgmt.get("automatic_management")
        )
        if auto_mgmt is False:
            account_name = detail.get("name") or detail.get("userName") or "unknown"
            reasons.append(f"Privileged account {account_name} — automatic management disabled")
            return False, reasons
        last_modified = secret_mgmt.get("lastModifiedTime") or secret_mgmt.get("last_modified")
        if last_modified:
            days = _days_since(str(last_modified))
            if days is not None and days > 90:
                account_name = detail.get("name") or detail.get("userName") or "unknown"
                reasons.append(
                    f"Privileged account {account_name} — password not rotated in {days} days"
                )
                return False, reasons

    # CyberArk compliance shape
    compliant = detail.get("compliant") or detail.get("is_compliant")
    if compliant is False:
        non_compliant = detail.get("non_compliant_accounts") or detail.get("nonCompliantCount", 0)
        reasons.append(f"CyberArk compliance check failed — {non_compliant} non-compliant accounts")
        return False, reasons

    # Safe-level checks
    detail.get("numberOfDaysRetention")
    if platform_id and safe_name:
        return True, []

    return True, []


@engine.assertion("access_reviews_current")
def access_reviews_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that access certifications/reviews are complete (SailPoint)."""
    reasons: list[str] = []

    # SailPoint certification shape
    phase = detail.get("phase") or detail.get("status")
    completed = detail.get("completed")

    if phase is not None:
        phase_lower = str(phase).lower()
        if phase_lower in ("expired", "overdue"):
            campaign = detail.get("name") or detail.get("campaign_name") or "unknown"
            reasons.append(f"Access review campaign '{campaign}' is {phase_lower}")
            return False, reasons

    if completed is False:
        due_date = detail.get("deadline") or detail.get("due_date") or detail.get("endDate")
        if due_date:
            days = _days_since(str(due_date))
            if days is not None and days > 0:
                campaign = detail.get("name") or detail.get("campaign_name") or "unknown"
                reasons.append(f"Access review campaign '{campaign}' is overdue by {days} days")
                return False, reasons

    # Completion percentage
    total = detail.get("totalCertifications") or detail.get("total", 0)
    completed_count = detail.get("completedCertifications") or detail.get("completed_count", 0)
    if total and completed_count:
        pct = (completed_count / total) * 100
        if pct < 90:
            reasons.append(f"Access review completion at {pct:.0f}% ({completed_count}/{total})")
            return False, reasons

    return True, []


@engine.assertion("siem_monitoring_active")
def siem_monitoring_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that SIEM has active detection rules (Splunk, Sentinel, Elastic)."""
    reasons: list[str] = []

    # Splunk saved searches / correlation rules
    rules = detail.get("rules", detail.get("saved_searches", []))
    if isinstance(rules, list) and len(rules) == 0 and detail.get("total_rules") is not None:
        if detail.get("total_rules", 0) == 0:
            reasons.append("No SIEM detection rules configured")
            return False, reasons

    # Sentinel analytics rules shape
    enabled_rules = detail.get("enabled_rules") or detail.get("enabledRuleCount")
    total_rules = detail.get("total_rules") or detail.get("totalRuleCount")
    if total_rules is not None and enabled_rules is not None:
        if enabled_rules == 0:
            reasons.append("No SIEM detection rules are enabled")
            return False, reasons
        if total_rules > 0 and (enabled_rules / total_rules) < 0.5:
            reasons.append(f"Only {enabled_rules}/{total_rules} SIEM detection rules enabled")
            return False, reasons

    # Individual rule status check
    rule_status = detail.get("status") or detail.get("enabled")
    if rule_status is not None:
        if str(rule_status).lower() in ("disabled", "false") or rule_status is False:
            rule_name = detail.get("name") or detail.get("displayName") or "unknown"
            reasons.append(f"SIEM detection rule '{rule_name}' is disabled")
            return False, reasons

    # Elastic detection rules
    elastic_rules = detail.get("detection_rules", [])
    if isinstance(elastic_rules, list) and elastic_rules:
        disabled = [r for r in elastic_rules if not r.get("enabled", True)]
        if len(disabled) == len(elastic_rules):
            reasons.append("All Elastic detection rules are disabled")
            return False, reasons

    # Data connector health (Sentinel)
    connector_status = detail.get("connectorStatus") or detail.get("connector_status")
    if connector_status is not None and str(connector_status).lower() != "connected":
        connector_name = detail.get("connectorName") or detail.get("name") or "unknown"
        reasons.append(f"SIEM data connector '{connector_name}' status: {connector_status}")
        return False, reasons

    return True, []


# ---------------------------------------------------------------------------
# Control bindings — NIST 800-53
# ---------------------------------------------------------------------------

_NIST_BINDINGS: list[tuple[str, str]] = [
    ("AC-2", "mfa_enabled"),
    ("AC-2", "no_root_access_keys"),
    ("AC-6", "no_root_access_keys"),
    ("AC-6", "privileged_access_managed"),
    ("AC-17", "no_open_security_groups"),
    ("AU-2", "cloudtrail_enabled"),
    ("AU-12", "cloudtrail_enabled"),
    ("CM-2", "config_recorder_enabled"),
    ("CM-6", "config_recorder_enabled"),
    ("IA-2", "mfa_enabled"),
    ("IA-5", "password_policy_compliant"),
    ("SC-7", "no_open_security_groups"),
    ("SC-28", "encryption_at_rest"),
    ("SI-2", "vulnerability_scan_current"),
    ("SI-3", "endpoint_protection_active"),
    ("SI-4", "guardduty_enabled"),
    ("SI-5", "securityhub_enabled"),
    ("RA-5", "vulnerability_scan_current"),
    ("IR-5", "siem_monitoring_active"),
    ("CA-7", "config_recorder_enabled"),
    ("PS-4", "access_reviews_current"),
]

for _ctrl, _assertion in _NIST_BINDINGS:
    engine.bind_control("nist_800_53", _ctrl, _assertion)

# ---------------------------------------------------------------------------
# Control bindings — SOC 2
# ---------------------------------------------------------------------------

_SOC2_BINDINGS: list[tuple[str, str]] = [
    ("CC6.1", "mfa_enabled"),
    ("CC6.3", "privileged_access_managed"),
    ("CC6.6", "no_open_security_groups"),
    ("CC6.7", "no_public_storage"),
    ("CC6.8", "endpoint_protection_active"),
    ("CC7.1", "guardduty_enabled"),
    ("CC7.2", "cloudtrail_enabled"),
    ("CC7.3", "config_recorder_enabled"),
    ("CC7.4", "siem_monitoring_active"),
    ("CC3.1", "vulnerability_scan_current"),
    ("CC9.1", "vulnerability_scan_current"),
    ("C1.1", "encryption_at_rest"),
]

for _ctrl, _assertion in _SOC2_BINDINGS:
    engine.bind_control("soc2", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — ISO 27001:2022
# ---------------------------------------------------------------------------

_ISO27001_BINDINGS: list[tuple[str, str]] = [
    ("A.5.7", "guardduty_enabled"),  # Threat intelligence
    ("A.5.15", "mfa_enabled"),  # Access control
    ("A.5.16", "access_reviews_current"),  # Identity management
    ("A.5.17", "password_policy_compliant"),  # Authentication information
    ("A.5.23", "config_recorder_enabled"),  # Cloud services
    ("A.5.25", "siem_monitoring_active"),  # Assessment of security events
    ("A.5.26", "siem_monitoring_active"),  # Response to incidents
    ("A.6.5", "access_reviews_current"),  # After termination
    ("A.8.1", "device_compliant"),  # User endpoint devices
    ("A.8.2", "privileged_access_managed"),  # Privileged access rights
    ("A.8.5", "mfa_enabled"),  # Secure authentication
    ("A.8.7", "endpoint_protection_active"),  # Protection against malware
    ("A.8.8", "vulnerability_scan_current"),  # Management of technical vulnerabilities
    ("A.8.9", "config_recorder_enabled"),  # Configuration management
    ("A.8.15", "cloudtrail_enabled"),  # Logging
    ("A.8.16", "siem_monitoring_active"),  # Monitoring activities
    ("A.8.20", "no_open_security_groups"),  # Networks security
    ("A.8.22", "no_open_security_groups"),  # Segregation of networks
    ("A.8.24", "encryption_at_rest"),  # Use of cryptography
]

for _ctrl, _assertion in _ISO27001_BINDINGS:
    engine.bind_control("iso_27001", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — ISO 27701
# ---------------------------------------------------------------------------

_ISO27701_BINDINGS: list[tuple[str, str]] = [
    ("CL6.5.2.1", "mfa_enabled"),  # Access control
    ("CL6.5.3.1", "encryption_at_rest"),  # Cryptographic controls
    ("CL6.6.2.1", "cloudtrail_enabled"),  # Event logging
    ("CL6.8.2.1", "no_open_security_groups"),  # Network security
    ("CL6.9.3.1", "encryption_at_rest"),  # Protection of records
    ("A.7.4.5", "encryption_at_rest"),  # PII de-identification and deletion
    ("A.7.4.9", "encryption_at_rest"),  # PII transmission controls
    ("B.8.4.3", "encryption_at_rest"),  # Processor PII transmission
]

for _ctrl, _assertion in _ISO27701_BINDINGS:
    engine.bind_control("iso_27701", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — ISO 42001
# ---------------------------------------------------------------------------

_ISO42001_BINDINGS: list[tuple[str, str]] = [
    ("A.6.2.12", "siem_monitoring_active"),  # AI system operation and monitoring
    ("A.9.3", "mfa_enabled"),  # Misuse prevention — access
    ("A.9.4", "access_reviews_current"),  # Human oversight — reviews
]

for _ctrl, _assertion in _ISO42001_BINDINGS:
    engine.bind_control("iso_42001", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Assertions — new connectors
# ---------------------------------------------------------------------------


@engine.assertion("background_check_completed")
def background_check_completed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that employee background checks are completed."""
    reasons = []
    status = detail.get("background_check_status") or detail.get("status")
    if status and str(status).lower() not in ("completed", "passed", "clear"):
        name = detail.get("employee_name") or detail.get("name") or "unknown"
        reasons.append(f"Employee {name} background check status: {status}")
        return False, reasons
    if detail.get("background_check_missing"):
        name = detail.get("employee_name") or detail.get("name") or "unknown"
        reasons.append(f"Employee {name} has no background check on file")
        return False, reasons
    return True, []


@engine.assertion("employment_agreement_signed")
def employment_agreement_signed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that employment agreements and NDAs are signed."""
    reasons = []
    agreement = detail.get("agreement_signed") or detail.get("employment_agreement")
    nda = detail.get("nda_signed") or detail.get("confidentiality_agreement")
    name = detail.get("employee_name") or detail.get("name") or "unknown"
    if agreement is False or detail.get("agreement_missing"):
        reasons.append(f"Employee {name} has not signed employment agreement")
    if nda is False or detail.get("nda_missing"):
        reasons.append(f"Employee {name} has not signed NDA/confidentiality agreement")
    if reasons:
        return False, reasons
    return True, []


@engine.assertion("change_request_approved")
def change_request_approved(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that change requests have proper approval before implementation."""
    reasons = []
    approval = detail.get("approval") or detail.get("approval_status") or ""
    if str(approval).lower() not in ("approved", "completed", "accepted"):
        change_id = detail.get("number") or detail.get("change_id") or "unknown"
        reasons.append(f"Change {change_id} not approved (status: {approval})")
        return False, reasons
    backout = detail.get("backout_plan") or detail.get("rollback_plan") or ""
    if not backout.strip():
        change_id = detail.get("number") or detail.get("change_id") or "unknown"
        reasons.append(f"Change {change_id} has no rollback/backout plan")
        return False, reasons
    return True, []


@engine.assertion("training_completion_rate")
def training_completion_rate(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check security awareness training completion meets threshold."""
    reasons = []
    # Campaign level
    completion_pct = detail.get("completion_pct") or detail.get("completion_rate")
    if completion_pct is not None:
        if float(completion_pct) < 95.0:
            campaign = detail.get("campaign_name") or detail.get("name") or "unknown"
            reasons.append(
                f"Training campaign '{campaign}' completion at {completion_pct}% (target: 95%)"
            )
            return False, reasons
        return True, []
    # Individual enrollment level
    status = detail.get("status") or detail.get("enrollment_status") or ""
    if str(status).lower() in ("overdue", "past_due", "not_started"):
        user = detail.get("user") or detail.get("email") or "unknown"
        reasons.append(f"User {user} training status: {status}")
        return False, reasons
    return True, []


@engine.assertion("phishing_failure_rate")
def phishing_failure_rate(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check phishing simulation click rate is below threshold."""
    reasons = []
    click_rate = detail.get("click_rate") or detail.get("phish_prone_percentage")
    if click_rate is not None and float(click_rate) > 5.0:
        reasons.append(f"Phishing click rate at {click_rate}% (target: <5%)")
        return False, reasons
    clicked = detail.get("clicked") or detail.get("was_clicked")
    if clicked is True:
        user = detail.get("user") or detail.get("email") or "unknown"
        reasons.append(f"User {user} clicked phishing simulation")
        return False, reasons
    return True, []


@engine.assertion("no_critical_code_vulns")
def no_critical_code_vulns(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that no critical/high code vulnerabilities are open."""
    reasons = []
    severity = detail.get("severity") or detail.get("issue_severity") or ""
    if str(severity).lower() in ("critical", "high"):
        title = detail.get("title") or detail.get("issue_title") or "unknown"
        pkg = detail.get("package") or detail.get("package_name") or ""
        reasons.append(
            f"Open {severity} code vulnerability: {title}" + (f" in {pkg}" if pkg else "")
        )
        return False, reasons
    return True, []


@engine.assertion("backup_job_successful")
def backup_job_successful(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that backup jobs completed successfully and RPO is met."""
    reasons = []
    status = detail.get("status") or detail.get("result") or ""
    if str(status).lower() in ("failed", "error", "warning"):
        job = detail.get("job_name") or detail.get("name") or "unknown"
        reasons.append(f"Backup job '{job}' status: {status}")
        return False, reasons
    # RPO check
    rpo_exceeded = detail.get("rpo_exceeded")
    if rpo_exceeded:
        reasons.append("RPO exceeded: last successful backup more than target hours ago")
        return False, reasons
    return True, []


@engine.assertion("device_compliant")
def device_compliant(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that managed devices pass compliance policies."""
    reasons = []
    compliant = detail.get("complianceState") or detail.get("compliance_state") or ""
    if str(compliant).lower() in ("noncompliant", "non_compliant", "error", "conflict"):
        device = detail.get("deviceName") or detail.get("device_name") or "unknown"
        reasons.append(f"Device {device} compliance state: {compliant}")
        return False, reasons
    encrypted = detail.get("isEncrypted") or detail.get("is_encrypted")
    if encrypted is False:
        device = detail.get("deviceName") or detail.get("device_name") or "unknown"
        reasons.append(f"Device {device} disk is not encrypted")
        return False, reasons
    return True, []


@engine.assertion("policy_reviewed_within_year")
def policy_reviewed_within_year(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that policy/procedure documents have been reviewed within 365 days."""
    reasons = []
    last_updated = (
        detail.get("last_updated") or detail.get("modified_date") or detail.get("updated_at")
    )
    if last_updated:
        days = _days_since(str(last_updated))
        if days is not None and days > 365:
            title = detail.get("title") or detail.get("name") or "unknown"
            reasons.append(f"Document '{title}' last updated {days} days ago (>365)")
            return False, reasons
    return True, []


@engine.assertion("dlp_policies_active")
def dlp_policies_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that DLP policies are enabled and active."""
    reasons = []
    enabled = detail.get("isEnabled") or detail.get("enabled") or detail.get("state")
    if enabled is False or str(enabled).lower() in ("disabled", "off"):
        policy = detail.get("name") or detail.get("policy_name") or "unknown"
        reasons.append(f"DLP policy '{policy}' is disabled")
        return False, reasons
    return True, []


# ---------------------------------------------------------------------------
# Control bindings — new connectors
# ---------------------------------------------------------------------------

# Personnel / HR controls
_HR_BINDINGS = [
    # NIST PS family
    ("PS-3", "background_check_completed"),
    ("PS-6", "employment_agreement_signed"),
    ("PS-7", "employment_agreement_signed"),
]
for _ctrl, _assertion in _HR_BINDINGS:
    engine.bind_control("nist_800_53", _ctrl, _assertion)

engine.bind_control("iso_27001", "A.6.1", "background_check_completed")
engine.bind_control("iso_27001", "A.6.2", "employment_agreement_signed")
engine.bind_control("iso_27001", "A.6.6", "employment_agreement_signed")
engine.bind_control("soc2", "CC1.3", "background_check_completed")
engine.bind_control("soc2", "CC1.4", "training_completion_rate")
engine.bind_control("soc2", "CC1.5", "background_check_completed")
engine.bind_control("ucf", "UCF-HRS-1", "background_check_completed")
engine.bind_control("ucf", "UCF-HRS-2", "employment_agreement_signed")

# Change management
engine.bind_control("nist_800_53", "CM-3", "change_request_approved")
engine.bind_control("nist_800_53", "CM-4", "change_request_approved")
engine.bind_control("soc2", "CC8.1", "change_request_approved")
engine.bind_control("iso_27001", "A.8.32", "change_request_approved")
engine.bind_control("ucf", "UCF-CFG-2", "change_request_approved")

# Training & phishing
engine.bind_control("nist_800_53", "AT-2", "training_completion_rate")
engine.bind_control("nist_800_53", "AT-2", "phishing_failure_rate")
engine.bind_control("nist_800_53", "AT-3", "training_completion_rate")
engine.bind_control("nist_800_53", "AT-3", "phishing_failure_rate")
engine.bind_control("iso_27001", "A.6.3", "training_completion_rate")
engine.bind_control("iso_27001", "A.6.3", "phishing_failure_rate")
engine.bind_control("ucf", "UCF-HRS-3", "training_completion_rate")
engine.bind_control("ucf", "UCF-HRS-3", "phishing_failure_rate")

# Code security
engine.bind_control("nist_800_53", "SA-11", "no_critical_code_vulns")
engine.bind_control("iso_27001", "A.8.28", "no_critical_code_vulns")
engine.bind_control("iso_27001", "A.8.29", "no_critical_code_vulns")
engine.bind_control("ucf", "UCF-DEV-2", "no_critical_code_vulns")
engine.bind_control("ucf", "UCF-DEV-3", "no_critical_code_vulns")

# Backup
engine.bind_control("nist_800_53", "CP-9", "backup_job_successful")
engine.bind_control("nist_800_53", "CP-10", "backup_job_successful")
engine.bind_control("soc2", "A1.1", "backup_job_successful")
engine.bind_control("soc2", "A1.2", "backup_job_successful")
engine.bind_control("soc2", "A1.3", "backup_job_successful")
engine.bind_control("iso_27001", "A.8.13", "backup_job_successful")
engine.bind_control("ucf", "UCF-BCP-2", "backup_job_successful")

# MDM / Device compliance
engine.bind_control("nist_800_53", "AC-19", "device_compliant")
engine.bind_control("ucf", "UCF-EPP-4", "device_compliant")

# DLP
engine.bind_control("nist_800_53", "SC-7", "dlp_policies_active")
engine.bind_control("soc2", "CC6.7", "dlp_policies_active")
engine.bind_control("iso_27001", "A.8.12", "dlp_policies_active")
engine.bind_control("ucf", "UCF-DAT-7", "dlp_policies_active")

# Policy/document management
engine.bind_control("iso_27001", "A.5.1", "policy_reviewed_within_year")
engine.bind_control("iso_27001", "A.5.37", "policy_reviewed_within_year")
engine.bind_control("ucf", "UCF-GOV-6", "policy_reviewed_within_year")


# ---------------------------------------------------------------------------
# Control bindings — PCI DSS 4.0
# ---------------------------------------------------------------------------

_PCI_DSS_BINDINGS: list[tuple[str, str]] = [
    # R1: Network Security Controls
    ("R1.1", "no_open_security_groups"),
    ("R1.2", "no_open_security_groups"),
    ("R1.3", "no_open_security_groups"),
    ("R1.4", "endpoint_protection_active"),
    ("R1.5", "config_recorder_enabled"),
    # R2: Secure Configurations
    ("R2.1", "config_recorder_enabled"),
    ("R2.2", "config_recorder_enabled"),
    # R3: Protect Stored Account Data
    ("R3.2", "dlp_policies_active"),
    ("R3.3", "encryption_at_rest"),
    ("R3.4", "encryption_at_rest"),
    ("R3.5", "encryption_at_rest"),
    ("R3.6", "encryption_at_rest"),
    # R4: Cryptography During Transmission
    ("R4.2", "dlp_policies_active"),
    # R5: Malicious Software Protection
    ("R5.1", "endpoint_protection_active"),
    ("R5.2", "endpoint_protection_active"),
    ("R5.3", "endpoint_protection_active"),
    ("R5.4", "phishing_failure_rate"),
    # R6: Secure Systems and Software
    ("R6.1", "no_critical_code_vulns"),
    ("R6.2", "no_critical_code_vulns"),
    ("R6.3", "vulnerability_scan_current"),
    ("R6.4", "vulnerability_scan_current"),
    ("R6.5", "change_request_approved"),
    # R7: Access Restriction
    ("R7.1", "access_reviews_current"),
    ("R7.2", "access_reviews_current"),
    ("R7.3", "access_reviews_current"),
    # R8: Authentication
    ("R8.1", "mfa_enabled"),
    ("R8.2", "mfa_enabled"),
    ("R8.3", "password_policy_compliant"),
    ("R8.4", "mfa_enabled"),
    ("R8.5", "mfa_enabled"),
    ("R8.6", "privileged_access_managed"),
    # R10: Logging and Monitoring
    ("R10.1", "cloudtrail_enabled"),
    ("R10.2", "cloudtrail_enabled"),
    ("R10.3", "cloudtrail_enabled"),
    ("R10.4", "siem_monitoring_active"),
    ("R10.5", "cloudtrail_enabled"),
    ("R10.7", "siem_monitoring_active"),
    # R11: Security Testing
    ("R11.3", "vulnerability_scan_current"),
    ("R11.5", "guardduty_enabled"),
    ("R11.6", "config_recorder_enabled"),
    # R12: Policies and Programs
    ("R12.1", "policy_reviewed_within_year"),
    ("R12.2", "policy_reviewed_within_year"),
    ("R12.6", "training_completion_rate"),
    ("R12.7", "background_check_completed"),
    ("R12.10", "siem_monitoring_active"),
]

for _ctrl, _assertion in _PCI_DSS_BINDINGS:
    engine.bind_control("pci_dss", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — NIST CSF 2.0
# ---------------------------------------------------------------------------

_NIST_CSF_BINDINGS: list[tuple[str, str]] = [
    # Govern
    ("GV.PO-01", "policy_reviewed_within_year"),
    ("GV.PO-02", "policy_reviewed_within_year"),
    ("GV.RR-04", "training_completion_rate"),
    # Identify
    ("ID.RA-01", "vulnerability_scan_current"),
    ("ID.RA-02", "guardduty_enabled"),
    ("ID.RA-03", "guardduty_enabled"),
    # Protect
    ("PR.AA-01", "access_reviews_current"),
    ("PR.AA-03", "mfa_enabled"),
    ("PR.AA-04", "privileged_access_managed"),
    ("PR.AA-05", "access_reviews_current"),
    ("PR.AT-01", "training_completion_rate"),
    ("PR.AT-01", "phishing_failure_rate"),
    ("PR.DS-01", "encryption_at_rest"),
    ("PR.DS-02", "no_open_security_groups"),
    ("PR.DS-11", "backup_job_successful"),
    ("PR.PS-01", "config_recorder_enabled"),
    ("PR.PS-02", "vulnerability_scan_current"),
    ("PR.PS-04", "cloudtrail_enabled"),
    ("PR.PS-06", "no_critical_code_vulns"),
    ("PR.IR-01", "no_open_security_groups"),
    # Detect
    ("DE.CM-01", "guardduty_enabled"),
    ("DE.CM-01", "securityhub_enabled"),
    ("DE.CM-09", "endpoint_protection_active"),
    ("DE.AE-02", "siem_monitoring_active"),
    ("DE.AE-03", "siem_monitoring_active"),
    # Respond
    ("RS.MA-01", "siem_monitoring_active"),
    ("RS.MA-05", "vulnerability_scan_current"),
    # Recover
    ("RC.RP-01", "backup_job_successful"),
]

for _ctrl, _assertion in _NIST_CSF_BINDINGS:
    engine.bind_control("nist_csf", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — ISO 42001 (expanded from 3 to 20+)
# ---------------------------------------------------------------------------

_ISO42001_EXTRA_BINDINGS: list[tuple[str, str]] = [
    ("A.2.2", "policy_reviewed_within_year"),  # AI policy document review
    ("A.2.4", "policy_reviewed_within_year"),  # AI lifecycle policy review
    ("A.3.2", "access_reviews_current"),  # Roles and responsibilities
    ("A.4.3", "training_completion_rate"),  # Competence — training
    ("A.4.4", "training_completion_rate"),  # Awareness — training
    ("A.5.2", "vulnerability_scan_current"),  # Impact assessment — scanning
    ("A.5.4", "guardduty_enabled"),  # Ongoing impact monitoring
    ("A.6.1.2", "policy_reviewed_within_year"),  # Responsible AI principles
    ("A.6.2.3", "config_recorder_enabled"),  # Verification/validation
    ("A.6.2.5", "encryption_at_rest"),  # Data management — encryption
    ("A.6.2.6", "no_public_storage"),  # Data preparation — no public
    ("A.6.2.11", "change_request_approved"),  # System deployment — change mgmt
    ("A.7.2", "config_recorder_enabled"),  # Data quality
    ("A.7.3", "cloudtrail_enabled"),  # Data provenance — audit trail
    ("A.7.4", "encryption_at_rest"),  # Data preparation — encrypted
    ("A.7.5", "cloudtrail_enabled"),  # Acquiring data — audit
    ("A.9.3", "no_open_security_groups"),  # Misuse prevention — network
    ("A.10.3", "access_reviews_current"),  # Supplier monitoring — reviews
]

for _ctrl, _assertion in _ISO42001_EXTRA_BINDINGS:
    engine.bind_control("iso_42001", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — EU AI Act
# ---------------------------------------------------------------------------

_EU_AI_ACT_BINDINGS: list[tuple[str, str]] = [
    ("ART9.1", "policy_reviewed_within_year"),  # Risk management system
    ("ART9.2", "vulnerability_scan_current"),  # Risk identification
    ("ART10.1", "encryption_at_rest"),  # Training data protection
    ("ART10.2", "encryption_at_rest"),  # Data governance
    ("ART12.1", "cloudtrail_enabled"),  # Automatic logging
    ("ART12.2", "cloudtrail_enabled"),  # Traceability
    ("ART14.1", "access_reviews_current"),  # Human oversight
    ("ART14.3", "training_completion_rate"),  # Human understanding
    ("ART15.3", "endpoint_protection_active"),  # Resilience
    ("ART15.4", "guardduty_enabled"),  # Cybersecurity
    ("ART15.4", "no_open_security_groups"),  # Cybersecurity — network
    ("ART26.2", "siem_monitoring_active"),  # Deployer monitoring
]

for _ctrl, _assertion in _EU_AI_ACT_BINDINGS:
    engine.bind_control("eu_ai_act", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — SEC Cybersecurity Disclosure Rules
# ---------------------------------------------------------------------------

_SEC_CYBER_BINDINGS: list[tuple[str, str]] = [
    ("ITEM105.1", "siem_monitoring_active"),  # Incident determination
    ("ITEM106.B1", "policy_reviewed_within_year"),  # Risk management program
    ("ITEM106.B2", "vulnerability_scan_current"),  # Risk assessment process
    ("ITEM106.C5", "training_completion_rate"),  # Management expertise
    ("ITEM106.C6", "siem_monitoring_active"),  # Prevention/detection
    ("ANN.1", "policy_reviewed_within_year"),  # Annual disclosure
]

for _ctrl, _assertion in _SEC_CYBER_BINDINGS:
    engine.bind_control("sec_cyber", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — CMMC L2 (all 14 domains)
# ---------------------------------------------------------------------------

_CMMC_L2_BINDINGS: list[tuple[str, str]] = [
    # AC — Access Control
    ("AC.L2-3.1.1", "mfa_enabled"),
    ("AC.L2-3.1.1", "access_reviews_current"),
    ("AC.L2-3.1.2", "privileged_access_managed"),
    ("AC.L2-3.1.3", "no_open_security_groups"),
    ("AC.L2-3.1.4", "access_reviews_current"),
    ("AC.L2-3.1.5", "privileged_access_managed"),
    ("AC.L2-3.1.6", "privileged_access_managed"),
    ("AC.L2-3.1.7", "cloudtrail_enabled"),
    ("AC.L2-3.1.12", "no_open_security_groups"),
    ("AC.L2-3.1.13", "no_open_security_groups"),
    ("AC.L2-3.1.14", "no_open_security_groups"),
    ("AC.L2-3.1.18", "device_compliant"),
    ("AC.L2-3.1.19", "encryption_at_rest"),
    ("AC.L2-3.1.20", "no_open_security_groups"),
    ("AC.L2-3.1.22", "no_public_storage"),
    # AT — Awareness and Training
    ("AT.L2-3.2.1", "training_completion_rate"),
    ("AT.L2-3.2.1", "phishing_failure_rate"),
    ("AT.L2-3.2.2", "training_completion_rate"),
    ("AT.L2-3.2.3", "training_completion_rate"),
    # AU — Audit and Accountability
    ("AU.L2-3.3.1", "cloudtrail_enabled"),
    ("AU.L2-3.3.2", "cloudtrail_enabled"),
    ("AU.L2-3.3.5", "siem_monitoring_active"),
    ("AU.L2-3.3.8", "cloudtrail_enabled"),
    ("AU.L2-3.3.9", "cloudtrail_enabled"),
    # CM — Configuration Management
    ("CM.L2-3.4.1", "config_recorder_enabled"),
    ("CM.L2-3.4.2", "config_recorder_enabled"),
    ("CM.L2-3.4.3", "change_request_approved"),
    ("CM.L2-3.4.4", "change_request_approved"),
    ("CM.L2-3.4.5", "change_request_approved"),
    ("CM.L2-3.4.6", "no_open_security_groups"),
    ("CM.L2-3.4.7", "no_open_security_groups"),
    ("CM.L2-3.4.8", "endpoint_protection_active"),
    ("CM.L2-3.4.9", "endpoint_protection_active"),
    # IA — Identification and Authentication
    ("IA.L2-3.5.1", "mfa_enabled"),
    ("IA.L2-3.5.2", "mfa_enabled"),
    ("IA.L2-3.5.3", "mfa_enabled"),
    ("IA.L2-3.5.7", "password_policy_compliant"),
    ("IA.L2-3.5.8", "password_policy_compliant"),
    ("IA.L2-3.5.10", "password_policy_compliant"),
    # IR — Incident Response
    ("IR.L2-3.6.1", "siem_monitoring_active"),
    ("IR.L2-3.6.2", "siem_monitoring_active"),
    # MA — Maintenance
    ("MA.L2-3.7.1", "change_request_approved"),
    ("MA.L2-3.7.4", "endpoint_protection_active"),
    ("MA.L2-3.7.5", "mfa_enabled"),
    # MP — Media Protection
    ("MP.L2-3.8.1", "no_public_storage"),
    ("MP.L2-3.8.2", "no_public_storage"),
    ("MP.L2-3.8.6", "encryption_at_rest"),
    ("MP.L2-3.8.9", "encryption_at_rest"),
    ("MP.L2-3.8.9", "backup_job_successful"),
    # PS — Personnel Security
    ("PS.L2-3.9.1", "background_check_completed"),
    ("PS.L2-3.9.2", "access_reviews_current"),
    # RA — Risk Assessment
    ("RA.L2-3.11.1", "vulnerability_scan_current"),
    ("RA.L2-3.11.2", "vulnerability_scan_current"),
    ("RA.L2-3.11.3", "vulnerability_scan_current"),
    # CA — Security Assessment
    ("CA.L2-3.12.1", "config_recorder_enabled"),
    ("CA.L2-3.12.3", "config_recorder_enabled"),
    ("CA.L2-3.12.3", "guardduty_enabled"),
    ("CA.L2-3.12.3", "securityhub_enabled"),
    # SC — System and Communications Protection
    ("SC.L2-3.13.1", "no_open_security_groups"),
    ("SC.L2-3.13.2", "no_open_security_groups"),
    ("SC.L2-3.13.5", "no_open_security_groups"),
    ("SC.L2-3.13.6", "no_open_security_groups"),
    ("SC.L2-3.13.8", "encryption_at_rest"),
    ("SC.L2-3.13.11", "encryption_at_rest"),
    ("SC.L2-3.13.16", "encryption_at_rest"),
    # SI — System and Information Integrity
    ("SI.L2-3.14.1", "vulnerability_scan_current"),
    ("SI.L2-3.14.2", "endpoint_protection_active"),
    ("SI.L2-3.14.3", "securityhub_enabled"),
    ("SI.L2-3.14.4", "siem_monitoring_active"),
    ("SI.L2-3.14.5", "siem_monitoring_active"),
    ("SI.L2-3.14.6", "guardduty_enabled"),
    ("SI.L2-3.14.7", "endpoint_protection_active"),
]

for _ctrl, _assertion in _CMMC_L2_BINDINGS:
    engine.bind_control("cmmc_l2", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Remediation guidance
# ---------------------------------------------------------------------------

engine.set_remediation(
    "mfa_enabled",
    {
        "summary": "Enable multi-factor authentication for all users with console/interactive access.",
        "steps": [
            "Identify all users without MFA enabled",
            "Enforce MFA via IAM policy, Okta sign-on policy, or Entra ID Conditional Access",
            "Require hardware security keys or authenticator apps (avoid SMS)",
            "Verify MFA enrollment via credential report or IdP dashboard",
        ],
        "console_path": "IAM > Users > Security credentials > MFA",
    },
)

engine.set_remediation(
    "no_root_access_keys",
    {
        "summary": "Remove all access keys from the root/admin account.",
        "steps": [
            "Sign in as the root user",
            "Navigate to Security Credentials",
            "Delete all active access keys",
            "Use IAM users or roles for programmatic access instead",
        ],
        "console_path": "IAM > Root user > Security credentials",
    },
)

engine.set_remediation(
    "cloudtrail_enabled",
    {
        "summary": "Enable CloudTrail with multi-region logging and log file validation.",
        "steps": [
            "Create or update a trail to cover all regions",
            "Enable log file validation",
            "Configure S3 bucket with appropriate retention and encryption",
            "Enable CloudWatch Logs integration for real-time alerting",
        ],
        "console_path": "CloudTrail > Trails",
    },
)

engine.set_remediation(
    "guardduty_enabled",
    {
        "summary": "Enable GuardDuty (or equivalent threat detection) in all regions.",
        "steps": [
            "Enable GuardDuty in each AWS region",
            "Configure a delegated administrator for multi-account setups",
            "Enable S3 protection and EKS audit log monitoring",
            "Set up SNS notifications for high-severity findings",
        ],
        "console_path": "GuardDuty > Settings",
    },
)

engine.set_remediation(
    "securityhub_enabled",
    {
        "summary": "Enable AWS SecurityHub for centralized security findings.",
        "steps": [
            "Enable SecurityHub in each region",
            "Enable AWS Foundational Security Best Practices standard",
            "Enable CIS AWS Foundations Benchmark standard",
            "Configure cross-region aggregation",
        ],
        "console_path": "SecurityHub > Settings",
    },
)

engine.set_remediation(
    "no_open_security_groups",
    {
        "summary": "Restrict security group ingress rules to remove unrestricted access on sensitive ports.",
        "steps": [
            "Identify security groups with 0.0.0.0/0 ingress on sensitive ports (22, 3389, DB ports)",
            "Replace broad CIDR rules with specific IP ranges or security group references",
            "Use AWS Systems Manager Session Manager instead of SSH where possible",
            "Implement network segmentation with VPC endpoints",
        ],
        "console_path": "VPC > Security Groups",
    },
)

engine.set_remediation(
    "encryption_at_rest",
    {
        "summary": "Enable encryption at rest for all storage resources.",
        "steps": [
            "Enable default encryption on S3 buckets (SSE-S3 or SSE-KMS)",
            "Enable encryption for EBS volumes, RDS instances, and DynamoDB tables",
            "For Azure, verify Storage Service Encryption is enabled",
            "For GCP, verify Cloud KMS keys are configured or Google-managed encryption is active",
        ],
        "console_path": "S3 > Bucket > Properties > Default encryption",
    },
)

engine.set_remediation(
    "password_policy_compliant",
    {
        "summary": "Update the password policy to meet compliance requirements.",
        "steps": [
            "Set minimum password length to 14 or more characters",
            "Require uppercase, lowercase, numbers, and symbols",
            "Configure password expiration (90 days recommended)",
            "Enable password reuse prevention (24 passwords)",
        ],
        "console_path": "IAM > Account settings > Password policy",
    },
)

engine.set_remediation(
    "config_recorder_enabled",
    {
        "summary": "Enable AWS Config recorder to track all resource configurations.",
        "steps": [
            "Create a configuration recorder that records all resource types",
            "Set up a delivery channel to an S3 bucket",
            "Enable AWS Config rules for continuous compliance evaluation",
            "Consider using conformance packs for framework-aligned rule sets",
        ],
        "console_path": "AWS Config > Settings",
    },
)

engine.set_remediation(
    "no_public_storage",
    {
        "summary": "Remove public access from all storage buckets and accounts.",
        "steps": [
            "Enable S3 Block Public Access at the account level",
            "Review and remove bucket policies granting public access",
            "Remove ACLs granting access to AllUsers or AuthenticatedUsers",
            "For Azure, disable public blob access on storage accounts",
        ],
        "console_path": "S3 > Block Public Access settings",
    },
)

engine.set_remediation(
    "endpoint_protection_active",
    {
        "summary": "Ensure all endpoints have active EDR agents.",
        "steps": [
            "Identify endpoints with offline or inactive agents",
            "Reinstall or restart agents on affected endpoints",
            "Verify sensor policies enforce prevention mode",
            "Implement automated alerting for agent health degradation",
        ],
        "console_path": "EDR Console > Host Management",
    },
)

engine.set_remediation(
    "vulnerability_scan_current",
    {
        "summary": "Ensure vulnerability scans are performed regularly (at least every 30 days).",
        "steps": [
            "Configure scheduled scans for all assets",
            "Verify scan coverage includes all network segments",
            "Remediate critical and high vulnerabilities within SLA",
            "Review scan exclusions to minimize blind spots",
        ],
        "console_path": "Vulnerability Scanner > Scan Policies",
    },
)

engine.set_remediation(
    "privileged_access_managed",
    {
        "summary": "Ensure all privileged accounts are managed through PAM with automatic rotation.",
        "steps": [
            "Onboard all privileged accounts to CyberArk (or equivalent PAM)",
            "Enable automatic password management and rotation",
            "Configure session recording for privileged sessions",
            "Review and remediate non-compliant accounts",
        ],
        "console_path": "CyberArk > Accounts",
    },
)

engine.set_remediation(
    "access_reviews_current",
    {
        "summary": "Complete all outstanding access certification campaigns.",
        "steps": [
            "Identify overdue or expired certification campaigns",
            "Escalate incomplete certifications to reviewers and managers",
            "Revoke access for uncertified entitlements",
            "Schedule recurring certification campaigns on a quarterly basis",
        ],
        "console_path": "SailPoint > Certifications",
    },
)

engine.set_remediation(
    "siem_monitoring_active",
    {
        "summary": "Ensure SIEM has active detection rules and connected data sources.",
        "steps": [
            "Review and enable detection rules aligned to MITRE ATT&CK",
            "Verify all critical data sources are connected and ingesting",
            "Configure alerting thresholds and notification channels",
            "Test detection rules with simulated attack scenarios",
        ],
        "console_path": "SIEM > Detection Rules",
    },
)

engine.set_remediation(
    "background_check_completed",
    {
        "summary": "Ensure all employees have completed background checks before or shortly after hire.",
        "steps": [
            "Identify employees without completed background checks",
            "Initiate background check process through HR/Workday",
            "Set automated triggers for new hire background checks",
            "Track completion status and follow up on delays",
        ],
        "console_path": "Workday > Staffing > Background Checks",
    },
)

engine.set_remediation(
    "employment_agreement_signed",
    {
        "summary": "Ensure all employees have signed employment agreements and NDAs.",
        "steps": [
            "Identify employees without signed agreements",
            "Send agreement documents for e-signature",
            "Configure onboarding workflow to require signatures before system access",
            "Audit quarterly for gaps",
        ],
        "console_path": "Workday > Documents > Agreements",
    },
)

engine.set_remediation(
    "change_request_approved",
    {
        "summary": "Ensure all changes have documented approval and rollback plans.",
        "steps": [
            "Review change management policy for approval requirements",
            "Configure ServiceNow to require approval before implementation",
            "Add rollback plan as required field on change request form",
            "Audit emergency changes for post-implementation review",
        ],
        "console_path": "ServiceNow > Change Management",
    },
)

engine.set_remediation(
    "training_completion_rate",
    {
        "summary": "Ensure security awareness training completion meets organizational targets.",
        "steps": [
            "Identify users with overdue or incomplete training",
            "Send reminder notifications through KnowBe4",
            "Escalate chronic non-completers to management",
            "Configure automated enrollment for new hires within 30 days",
        ],
        "console_path": "KnowBe4 > Training > Campaigns",
    },
)

engine.set_remediation(
    "phishing_failure_rate",
    {
        "summary": "Reduce phishing simulation click rate below organizational threshold.",
        "steps": [
            "Review phishing simulation results by department",
            "Provide targeted training for high-risk users",
            "Increase simulation frequency for repeat offenders",
            "Report metrics to management quarterly",
        ],
        "console_path": "KnowBe4 > Phishing > Security Tests",
    },
)

engine.set_remediation(
    "no_critical_code_vulns",
    {
        "summary": "Remediate critical and high severity code vulnerabilities.",
        "steps": [
            "Triage critical/high findings in Snyk dashboard",
            "Apply available fixes and upgrade vulnerable packages",
            "If no fix available, evaluate compensating controls or risk acceptance",
            "Configure CI/CD to block merges with critical vulnerabilities",
        ],
        "console_path": "Snyk > Projects > Issues",
    },
)

engine.set_remediation(
    "backup_job_successful",
    {
        "summary": "Ensure backup jobs complete successfully and RPO targets are met.",
        "steps": [
            "Investigate failed backup job errors",
            "Verify backup storage capacity and connectivity",
            "Test restore from most recent backup",
            "Configure alerting for backup failures",
        ],
        "console_path": "Veeam > Jobs > Last Session",
    },
)

engine.set_remediation(
    "device_compliant",
    {
        "summary": "Ensure all managed devices meet compliance policies.",
        "steps": [
            "Review non-compliant devices in Intune portal",
            "Enable disk encryption (BitLocker/FileVault) on non-encrypted devices",
            "Push OS updates to devices with outdated versions",
            "Configure conditional access to block non-compliant devices",
        ],
        "console_path": "Intune > Devices > Compliance",
    },
)

engine.set_remediation(
    "policy_reviewed_within_year",
    {
        "summary": "Ensure all security policies and procedures are reviewed annually.",
        "steps": [
            "Identify documents not reviewed within 365 days",
            "Assign document owners to review and update content",
            "Update revision date and approval signatures",
            "Schedule recurring annual review calendar reminders",
        ],
        "console_path": "Confluence > Space > Pages",
    },
)

engine.set_remediation(
    "dlp_policies_active",
    {
        "summary": "Ensure DLP policies are enabled and actively monitoring data flows.",
        "steps": [
            "Review disabled DLP policies in Purview compliance portal",
            "Enable policies or update if requirements have changed",
            "Verify policy conditions and actions are correctly configured",
            "Test policies with synthetic sensitive data",
        ],
        "console_path": "Microsoft Purview > Data Loss Prevention > Policies",
    },
)


# ---------------------------------------------------------------------------
# Control bindings — GDPR
# ---------------------------------------------------------------------------

_GDPR_BINDINGS: list[tuple[str, str]] = [
    # Art 5 — Principles of Processing
    ("Art5-1a", "policy_reviewed_within_year"),  # Lawfulness
    ("Art5-1b", "policy_reviewed_within_year"),  # Purpose limitation
    ("Art5-1f", "encryption_at_rest"),  # Integrity and confidentiality
    ("Art5-1f", "dlp_policies_active"),  # Integrity and confidentiality
    # Art 25 — Data Protection by Design
    ("Art25-1", "encryption_at_rest"),
    ("Art25-1", "no_public_storage"),
    # Art 28 — Processor Obligations
    ("Art28-1", "access_reviews_current"),
    # Art 30 — Records of Processing
    ("Art30-1", "policy_reviewed_within_year"),
    # Art 32 — Security of Processing
    ("Art32-1", "encryption_at_rest"),
    ("Art32-1", "mfa_enabled"),
    ("Art32-1", "no_open_security_groups"),
    # Art 33 — Breach Notification
    ("Art33-1", "siem_monitoring_active"),
    # Art 35 — DPIA
    ("Art35-1", "policy_reviewed_within_year"),
]

for _ctrl, _assertion in _GDPR_BINDINGS:
    engine.bind_control("gdpr", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — HIPAA
# ---------------------------------------------------------------------------

_HIPAA_BINDINGS: list[tuple[str, str]] = [
    # 164.308 — Administrative Safeguards
    ("164.308(a)(1)(i)", "vulnerability_scan_current"),  # Risk Analysis
    ("164.308(a)(3)(i)", "background_check_completed"),  # Workforce Security
    ("164.308(a)(3)(i)", "access_reviews_current"),  # Workforce Security
    ("164.308(a)(4)(i)", "mfa_enabled"),  # Access Management
    ("164.308(a)(4)(i)", "privileged_access_managed"),  # Access Management
    ("164.308(a)(5)(i)", "training_completion_rate"),  # Security Awareness
    ("164.308(a)(5)(i)", "phishing_failure_rate"),  # Security Awareness
    ("164.308(a)(6)(i)", "siem_monitoring_active"),  # Incident Response
    # 164.312 — Technical Safeguards
    ("164.312(a)(1)", "mfa_enabled"),  # Access Control
    ("164.312(a)(1)", "no_open_security_groups"),  # Access Control
    ("164.312(a)(2)(iv)", "encryption_at_rest"),  # Encryption
    ("164.312(b)", "cloudtrail_enabled"),  # Audit Controls
    ("164.312(b)", "config_recorder_enabled"),  # Audit Controls
    ("164.312(c)(1)", "no_critical_code_vulns"),  # Integrity
    ("164.312(d)", "mfa_enabled"),  # Authentication
    ("164.312(d)", "password_policy_compliant"),  # Authentication
    ("164.312(e)(1)", "encryption_at_rest"),  # Transmission Security
    # 164.310 — Physical Safeguards
    ("164.310(d)(1)", "device_compliant"),  # Device Controls
]

for _ctrl, _assertion in _HIPAA_BINDINGS:
    engine.bind_control("hipaa", _ctrl, _assertion)


# ============================================================================
# NEW ASSERTIONS — 76 additional assertions (101 total)
# Organized by NIST 800-53 control family
# ============================================================================


# ---------------------------------------------------------------------------
# Network Security (SC family)
# ---------------------------------------------------------------------------


@engine.assertion("tls_version_current")
def tls_version_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify TLS 1.2+ on all endpoints.

    Checks Cloudflare SSL settings, load balancer configs, VPN tunnel versions.
    """
    reasons: list[str] = []

    # Cloudflare SSL/TLS settings
    min_tls = detail.get("min_tls_version") or detail.get("minTlsVersion") or ""
    if min_tls:
        if min_tls in ("1.0", "1.1"):
            reasons.append(f"Minimum TLS version is {min_tls} — requires 1.2+")
            return False, reasons
        return True, []

    # AWS ALB/NLB TLS policy
    ssl_policy = detail.get("SslPolicy") or detail.get("ssl_policy") or ""
    if ssl_policy:
        weak_policies = {
            "ELBSecurityPolicy-2016-08",
            "ELBSecurityPolicy-TLS-1-0-2015-04",
            "ELBSecurityPolicy-TLS-1-1-2017-01",
        }
        if ssl_policy in weak_policies:
            reasons.append(f"Load balancer uses weak TLS policy: {ssl_policy}")
            return False, reasons
        return True, []

    # Azure Application Gateway / Front Door
    min_protocol = detail.get("minProtocolVersion") or detail.get("min_protocol_version") or ""
    if min_protocol:
        if min_protocol.lower() in ("tls1_0", "tls1.0", "tls1_1", "tls1.1", "1.0", "1.1"):
            reasons.append(f"Minimum protocol version is {min_protocol} — requires TLS 1.2+")
            return False, reasons
        return True, []

    # VPN tunnel TLS version
    tls_version = detail.get("tls_version") or detail.get("tlsVersion") or ""
    if tls_version:
        if str(tls_version) in ("1.0", "1.1", "TLSv1", "TLSv1.1"):
            reasons.append(f"VPN tunnel uses TLS {tls_version} — requires 1.2+")
            return False, reasons
        return True, []

    # Issues list
    issues = detail.get("issues", [])
    if isinstance(issues, list):
        for issue in issues:
            if "tls" in str(issue).lower() and ("1.0" in str(issue) or "1.1" in str(issue)):
                reasons.append(f"TLS issue: {issue}")
        if reasons:
            return False, reasons

    return False, ["Insufficient data to determine TLS version"]


@engine.assertion("network_segmentation_enforced")
def network_segmentation_enforced(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify network segments exist (VPCs, subnets, NSGs).

    Checks that workloads are segregated into separate network zones.
    """
    reasons: list[str] = []

    # AWS VPC shape
    vpcs = detail.get("vpcs", detail.get("VpcId", None))
    if isinstance(vpcs, list):
        if len(vpcs) < 2:
            reasons.append("Only one VPC — no network segmentation")
            return False, reasons
        return True, []
    if vpcs:
        return True, []

    # Subnet count
    subnets = detail.get("subnets", detail.get("Subnets", []))
    if isinstance(subnets, list):
        private = [s for s in subnets if not s.get("MapPublicIpOnLaunch", False)]
        if len(private) == 0 and len(subnets) > 0:
            reasons.append("No private subnets — all subnets are public")
            return False, reasons
        if subnets:
            return True, []

    # Azure VNet / NSG
    vnets = detail.get("virtualNetworks", detail.get("vnets", []))
    if isinstance(vnets, list) and vnets:
        return True, []
    if detail.get("vnetId") or detail.get("vnet_id"):
        return True, []

    # GCP VPC
    network = detail.get("network") or detail.get("selfLink")
    if network:
        return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "flat_network" in issues:
        reasons.append("Network is flat with no segmentation")
        return False, reasons

    return False, ["Insufficient data to verify network segmentation"]


@engine.assertion("waf_enabled")
def waf_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify WAF is active on web-facing resources.

    Checks Cloudflare WAF, AWS WAF, Azure WAF.
    """
    reasons: list[str] = []

    # Cloudflare WAF
    waf_status = detail.get("waf") or detail.get("waf_enabled")
    if waf_status is not None:
        if str(waf_status).lower() in ("off", "disabled", "false") or waf_status is False:
            zone = detail.get("zone_name") or detail.get("name") or "unknown"
            reasons.append(f"WAF is disabled on zone {zone}")
            return False, reasons
        return True, []

    # AWS WAF WebACL
    web_acl = detail.get("WebACL") or detail.get("web_acl") or detail.get("WebACLId")
    if web_acl:
        return True, []

    # AWS WAF association check — resource without WAF
    resource_arn = detail.get("ResourceArn") or detail.get("resource_arn")
    if resource_arn and not web_acl:
        reasons.append(f"Resource {resource_arn} has no WAF WebACL associated")
        return False, reasons

    # Azure WAF
    waf_policy = (
        detail.get("firewallPolicy")
        or detail.get("waf_policy")
        or detail.get("webApplicationFirewallConfiguration")
    )
    if waf_policy:
        enabled = waf_policy.get("enabled", True) if isinstance(waf_policy, dict) else True
        if not enabled:
            reasons.append("Azure WAF policy exists but is disabled")
            return False, reasons
        return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_waf" in issues:
        reasons.append("No WAF protection on web-facing resources")
        return False, reasons

    return False, ["Insufficient data to determine WAF status"]


@engine.assertion("dns_security_enabled")
def dns_security_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify DNSSEC or DNS filtering is active.

    Checks Zscaler URL filtering, Cloudflare DNS, DNSSEC.
    """
    reasons: list[str] = []

    # DNSSEC status
    dnssec = detail.get("dnssec") or detail.get("dnssec_status") or detail.get("DnssecStatus")
    if dnssec is not None:
        if str(dnssec).lower() in ("disabled", "unsigned", "off", "inactive"):
            zone = detail.get("zone_name") or detail.get("Name") or "unknown"
            reasons.append(f"DNSSEC is not enabled for zone {zone}")
            return False, reasons
        return True, []

    # Cloudflare DNS settings
    dns_filtering = detail.get("dns_filtering") or detail.get("gateway_enabled")
    if dns_filtering is not None:
        if dns_filtering is False or str(dns_filtering).lower() in ("disabled", "off"):
            reasons.append("DNS filtering is not enabled")
            return False, reasons
        return True, []

    # Zscaler URL filtering
    url_filtering = detail.get("url_filtering_policy") or detail.get("urlFilteringRules")
    if url_filtering:
        return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_dns_security" in issues:
        reasons.append("No DNS security measures active")
        return False, reasons

    return False, ["Insufficient data to determine DNS security status"]


@engine.assertion("vpn_tunnel_active")
def vpn_tunnel_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify VPN tunnels are up and certificates not expired.

    Checks Fortinet, Palo Alto, Zscaler, AWS Site-to-Site VPN.
    """
    reasons: list[str] = []

    # Tunnel status
    tunnel_status = (
        detail.get("status") or detail.get("tunnel_status") or detail.get("tunnelStatus")
    )
    if tunnel_status is not None:
        if str(tunnel_status).lower() in ("down", "inactive", "disconnected", "failed"):
            tunnel_name = (
                detail.get("name")
                or detail.get("tunnel_name")
                or detail.get("VpnTunnelOutsideIpAddress")
                or "unknown"
            )
            reasons.append(f"VPN tunnel {tunnel_name} is {tunnel_status}")
            return False, reasons

    # AWS VPN tunnel shape
    tunnels = detail.get("VgwTelemetry", detail.get("tunnels", []))
    if isinstance(tunnels, list):
        for t in tunnels:
            t_status = t.get("Status", t.get("status", ""))
            if str(t_status).lower() == "down":
                ip = t.get("OutsideIpAddress", t.get("outside_ip", "unknown"))
                reasons.append(f"VPN tunnel to {ip} is DOWN")
        if reasons:
            return False, reasons
        if tunnels:
            return True, []

    # Certificate expiry
    cert_expiry = (
        detail.get("cert_expiry") or detail.get("certificate_expiry") or detail.get("certExpiry")
    )
    if cert_expiry:
        days = _days_since(str(cert_expiry))
        if days is not None and days > 0:
            reasons.append(f"VPN certificate expired {days} days ago")
            return False, reasons
        if days is not None and days > -30:
            # Not expired but within 30 days — still pass but note it
            pass

    if tunnel_status and str(tunnel_status).lower() in ("up", "active", "connected"):
        return True, []

    return False, ["Insufficient data to determine VPN tunnel status"]


@engine.assertion("network_flow_logging")
def network_flow_logging(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify flow logs are enabled (VPC flow logs, NSG flow logs).

    Checks AWS VPC Flow Logs, Azure NSG Flow Logs, GCP VPC Flow Logs.
    """
    reasons: list[str] = []

    # AWS VPC Flow Logs
    flow_logs = detail.get("FlowLogs", detail.get("flow_logs", []))
    if isinstance(flow_logs, list):
        if len(flow_logs) == 0:
            vpc_id = detail.get("VpcId") or detail.get("vpc_id") or "unknown"
            reasons.append(f"No flow logs enabled for VPC {vpc_id}")
            return False, reasons
        active = [f for f in flow_logs if f.get("FlowLogStatus", f.get("status", "")) == "ACTIVE"]
        if not active and flow_logs:
            reasons.append("Flow logs exist but none are active")
            return False, reasons
        return True, []

    # Azure NSG flow logs
    nsg_flow = detail.get("flowLogs") or detail.get("flow_log_settings")
    if isinstance(nsg_flow, dict):
        if not nsg_flow.get("enabled", False):
            nsg_name = detail.get("name") or "unknown"
            reasons.append(f"NSG flow logs not enabled for {nsg_name}")
            return False, reasons
        return True, []

    # GCP VPC flow logs
    log_config = detail.get("logConfig") or detail.get("log_config")
    if isinstance(log_config, dict):
        if not log_config.get("enable", False):
            subnet = detail.get("name") or "unknown"
            reasons.append(f"VPC flow logs not enabled for subnet {subnet}")
            return False, reasons
        return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_flow_logs" in issues:
        reasons.append("Network flow logging is not enabled")
        return False, reasons

    return False, ["Insufficient data to determine flow log status"]


@engine.assertion("egress_filtering_active")
def egress_filtering_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify outbound traffic is filtered.

    Checks Zscaler web policies, firewall egress rules, proxy configs.
    """
    reasons: list[str] = []

    # Zscaler web policies
    web_policy = detail.get("web_security_policy") or detail.get("urlFilteringRules")
    if web_policy:
        if isinstance(web_policy, dict) and web_policy.get("state") == "DISABLED":
            reasons.append("Zscaler web security policy is disabled")
            return False, reasons
        return True, []

    # Firewall egress rules
    egress_rules = (
        detail.get("egress_rules") or detail.get("outbound_rules") or detail.get("egressRules")
    )
    if isinstance(egress_rules, list):
        if len(egress_rules) == 0:
            reasons.append("No egress filtering rules configured")
            return False, reasons
        # Check for allow-all egress
        for rule in egress_rules:
            dest = rule.get("destination", rule.get("destinationAddressPrefix", ""))
            action = rule.get("action", rule.get("access", ""))
            if str(dest) in ("*", "0.0.0.0/0", "any") and str(action).lower() == "allow":
                protocol = rule.get("protocol", "all")
                reasons.append(f"Egress rule allows all traffic to {dest} ({protocol})")
        if reasons:
            return False, reasons
        return True, []

    # Proxy configured
    proxy = detail.get("proxy_enabled") or detail.get("proxyEnabled")
    if proxy is True:
        return True, []
    if proxy is False:
        reasons.append("Outbound proxy/filtering is disabled")
        return False, reasons

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_egress_filtering" in issues:
        reasons.append("No egress filtering configured")
        return False, reasons

    return False, ["Insufficient data to determine egress filtering status"]


@engine.assertion("wireless_security_compliant")
def wireless_security_compliant(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify wireless networks use WPA3/enterprise authentication.

    Checks wireless controller configs, Meraki, Aruba.
    """
    reasons: list[str] = []

    # Wireless security mode
    security_mode = (
        detail.get("security_mode") or detail.get("authMode") or detail.get("encryptionMode")
    )
    if security_mode:
        weak_modes = {"open", "wep", "wpa", "wpa-personal", "wpa2-personal", "psk"}
        if str(security_mode).lower() in weak_modes:
            ssid = detail.get("ssid") or detail.get("name") or "unknown"
            reasons.append(f"Wireless network {ssid} uses weak security: {security_mode}")
            return False, reasons
        return True, []

    # Meraki SSID shape
    auth_mode = detail.get("authMode") or detail.get("auth_mode")
    if auth_mode:
        if str(auth_mode).lower() in ("open", "psk"):
            ssid = detail.get("name") or detail.get("ssid") or "unknown"
            reasons.append(f"SSID {ssid} uses {auth_mode} — requires enterprise auth")
            return False, reasons
        return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "weak_wireless" in issues:
        reasons.append("Wireless security does not meet enterprise standards")
        return False, reasons

    return False, ["Insufficient data to determine wireless security"]


# ---------------------------------------------------------------------------
# Access Control (AC family)
# ---------------------------------------------------------------------------


@engine.assertion("least_privilege_enforced")
def least_privilege_enforced(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check for overly permissive IAM policies.

    Detects wildcard actions (*), admin policies, and full access grants
    across AWS IAM, Azure RBAC, and GCP IAM.
    """
    reasons: list[str] = []

    # AWS IAM policy document
    policy_doc = (
        detail.get("PolicyDocument") or detail.get("policy_document") or detail.get("Document")
    )
    if isinstance(policy_doc, dict):
        statements = policy_doc.get("Statement", [])
        for stmt in statements if isinstance(statements, list) else []:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]
                if "*" in actions and "*" in resources:
                    reasons.append("IAM policy grants Action:* on Resource:* (full admin)")
                elif "*" in actions:
                    reasons.append(f"IAM policy grants Action:* on {resources}")

    # AWS managed policy names
    policy_name = detail.get("PolicyName") or detail.get("policy_name") or ""
    if policy_name:
        overprivileged = {"AdministratorAccess", "PowerUserAccess", "IAMFullAccess"}
        if policy_name in overprivileged:
            user = (
                detail.get("UserName")
                or detail.get("RoleName")
                or detail.get("GroupName")
                or "unknown"
            )
            reasons.append(f"Entity {user} has overprivileged policy: {policy_name}")

    # Azure RBAC
    role_name = detail.get("roleDefinitionName") or detail.get("role_name") or ""
    if role_name:
        if role_name in ("Owner", "Contributor") and detail.get("scope", "").count("/") <= 4:
            principal = detail.get("principalName") or detail.get("principal_name") or "unknown"
            reasons.append(f"Principal {principal} has broad Azure role: {role_name}")

    # GCP IAM
    role = detail.get("role") or ""
    if isinstance(role, dict):
        role = role.get("name", "") or str(role)
    if role and isinstance(role, str):
        if "admin" in role.lower() or role.endswith("/owner") or role == "roles/editor":
            member = (
                detail.get("member") or detail.get("members", ["unknown"])[0]
                if isinstance(detail.get("members"), list)
                else "unknown"
            )
            reasons.append(f"GCP member {member} has overprivileged role: {role}")

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list):
        for issue in issues:
            if "overprivileged" in str(issue).lower() or "wildcard" in str(issue).lower():
                reasons.append(f"Least privilege issue: {issue}")

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("session_timeout_configured")
def session_timeout_configured(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify session timeouts are set.

    Checks Okta, Entra ID, Cloudflare Access session policies.
    """
    reasons: list[str] = []

    # Okta sign-on policy
    max_session = detail.get("maxSessionLifetimeMinutes") or detail.get("max_session_lifetime")
    if max_session is not None:
        if int(max_session) > 480:  # 8 hours
            reasons.append(f"Session lifetime is {max_session} minutes (max recommended: 480)")
            return False, reasons
        return True, []

    # Entra ID conditional access session controls
    session_controls = _get(detail, "sessionControls", default=None) or _get(
        detail, "session_controls", default=None
    )
    if isinstance(session_controls, dict):
        sign_in_freq = session_controls.get("signInFrequency", {})
        if isinstance(sign_in_freq, dict):
            if not sign_in_freq.get("isEnabled", True):
                reasons.append("Sign-in frequency control is disabled")
                return False, reasons
            return True, []

    # Cloudflare Access session duration
    session_duration = detail.get("session_duration") or detail.get("sessionDuration")
    if session_duration:
        return True, []

    # Generic timeout check
    idle_timeout = (
        detail.get("idle_timeout") or detail.get("idleTimeout") or detail.get("inactivity_timeout")
    )
    if idle_timeout is not None:
        if int(idle_timeout) > 30:  # 30 minutes idle
            reasons.append(f"Idle timeout is {idle_timeout} minutes (max recommended: 30)")
            return False, reasons
        return True, []

    return False, ["Insufficient data to determine session timeout configuration"]


@engine.assertion("account_provisioning_automated")
def account_provisioning_automated(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify user provisioning is automated via IdP (SailPoint, Okta).

    Checks SCIM provisioning, lifecycle management configuration.
    """
    reasons: list[str] = []

    # Okta provisioning settings
    provisioning = detail.get("provisioning") or detail.get("provisioningSettings")
    if isinstance(provisioning, dict):
        if not provisioning.get("enabled", False):
            app = detail.get("label") or detail.get("name") or "unknown"
            reasons.append(f"Automated provisioning not enabled for app {app}")
            return False, reasons
        return True, []

    # SCIM status
    scim_enabled = detail.get("scim_enabled") or detail.get("scimEnabled")
    if scim_enabled is not None:
        if scim_enabled is False or str(scim_enabled).lower() in ("disabled", "off"):
            app = detail.get("name") or detail.get("app_name") or "unknown"
            reasons.append(f"SCIM provisioning not enabled for {app}")
            return False, reasons
        return True, []

    # SailPoint source connection status
    connection_status = detail.get("status") or detail.get("connectionStatus")
    if connection_status:
        if str(connection_status).lower() in ("disconnected", "error", "failed"):
            source = detail.get("name") or detail.get("source_name") or "unknown"
            reasons.append(f"Identity source {source} is {connection_status}")
            return False, reasons
        return True, []

    return False, ["Insufficient data to determine provisioning automation"]


@engine.assertion("inactive_accounts_disabled")
def inactive_accounts_disabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check for accounts with no login in 90 days.

    Reviews AWS IAM, Okta, Entra ID for dormant accounts.
    """
    reasons: list[str] = []

    # Last login date
    last_login = (
        detail.get("last_login")
        or detail.get("lastLogin")
        or detail.get("lastSignInDateTime")
        or detail.get("password_last_used")
        or detail.get("lastSignIn")
    )
    if last_login:
        days = _days_since(str(last_login))
        if days is not None and days > 90:
            user = (
                detail.get("user")
                or detail.get("login")
                or detail.get("userPrincipalName")
                or detail.get("UserName")
                or "unknown"
            )
            status = detail.get("status") or detail.get("accountEnabled") or "unknown"
            if str(status).lower() not in ("deprovisioned", "suspended", "disabled", "false"):
                reasons.append(f"Account {user} inactive for {days} days and still enabled")
                return False, reasons
        return True, []

    # AWS credential report — password last used
    pwd_last_used = detail.get("password_last_used")
    if pwd_last_used and pwd_last_used != "N/A":
        days = _days_since(str(pwd_last_used))
        if days is not None and days > 90:
            user = detail.get("user", "unknown")
            reasons.append(f"AWS user {user} password last used {days} days ago")
            return False, reasons

    # Bulk inactive account count
    inactive_count = detail.get("inactive_accounts") or detail.get("dormant_count")
    if inactive_count is not None and int(inactive_count) > 0:
        reasons.append(f"{inactive_count} inactive accounts detected (90+ days)")
        return False, reasons

    return True, []


@engine.assertion("separation_of_duties")
def separation_of_duties(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check that admin roles don't overlap with operational roles.

    Verifies segregation of duties in IAM role assignments.
    """
    reasons: list[str] = []

    # Conflicting roles check
    roles = detail.get("roles") or detail.get("assigned_roles") or detail.get("roleAssignments", [])
    if isinstance(roles, list) and len(roles) > 1:
        role_names = [
            r.get("name", r.get("roleName", str(r))) if isinstance(r, dict) else str(r)
            for r in roles
        ]
        admin_roles = [r for r in role_names if "admin" in r.lower() or "owner" in r.lower()]
        operational_roles = [
            r for r in role_names if "operator" in r.lower() or "contributor" in r.lower()
        ]
        if admin_roles and operational_roles:
            user = detail.get("user") or detail.get("principalName") or "unknown"
            reasons.append(
                f"User {user} has both admin ({', '.join(admin_roles)}) "
                f"and operational ({', '.join(operational_roles)}) roles"
            )
            return False, reasons

    # SoD violation flags
    sod_violation = detail.get("sod_violation") or detail.get("segregationViolation")
    if sod_violation is True:
        user = detail.get("user") or detail.get("identity") or "unknown"
        conflict = (
            detail.get("conflicting_entitlements") or detail.get("conflict_detail") or "unspecified"
        )
        reasons.append(f"SoD violation for {user}: {conflict}")
        return False, reasons

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "sod_violation" in issues:
        reasons.append("Separation of duties violation detected")
        return False, reasons

    return True, []


@engine.assertion("remote_access_authorized")
def remote_access_authorized(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify VPN/remote access requires MFA and is logged.

    Checks VPN auth policies, Zscaler ZPA, Cloudflare Access.
    """
    reasons: list[str] = []

    # MFA required for VPN
    mfa_required = detail.get("mfa_required") or detail.get("multifactorRequired")
    if mfa_required is False:
        service = detail.get("name") or detail.get("service_name") or "VPN"
        reasons.append(f"Remote access via {service} does not require MFA")
        return False, reasons

    # Logging enabled for remote access
    logging_enabled = detail.get("logging_enabled") or detail.get("auditLogging")
    if logging_enabled is False:
        service = detail.get("name") or detail.get("service_name") or "VPN"
        reasons.append(f"Remote access via {service} does not have audit logging enabled")

    # Cloudflare Access / ZPA application
    if detail.get("type") in ("self_hosted", "saas", "ssh", "vnc"):
        policies = detail.get("policies", [])
        if isinstance(policies, list) and len(policies) == 0:
            app = detail.get("name") or "unknown"
            reasons.append(f"Cloudflare Access app {app} has no access policies")
            return False, reasons

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("conditional_access_enforced")
def conditional_access_enforced(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify Entra ID conditional access policies are active.

    Checks policy state, grant controls, and conditions.
    """
    reasons: list[str] = []

    # Entra ID conditional access policy state
    state = detail.get("state") or detail.get("policy_state")
    if state is not None:
        if str(state).lower() in ("disabled", "enabledforreportingbutnotenforced"):
            policy_name = detail.get("displayName") or detail.get("name") or "unknown"
            reasons.append(f"Conditional access policy '{policy_name}' is {state}")
            return False, reasons
        if str(state).lower() == "enabled":
            return True, []

    # Grant controls check
    grant_controls = _get(detail, "grantControls", default=None)
    if isinstance(grant_controls, dict):
        built_in = grant_controls.get("builtInControls", [])
        if isinstance(built_in, list) and not built_in:
            policy_name = detail.get("displayName") or detail.get("name") or "unknown"
            reasons.append(f"Conditional access policy '{policy_name}' has no grant controls")
            return False, reasons
        return True, []

    # Conditional access policy count
    total_policies = detail.get("total_policies") or detail.get("totalPolicies")
    enabled_policies = detail.get("enabled_policies") or detail.get("enabledPolicies")
    if total_policies is not None and enabled_policies is not None:
        if int(enabled_policies) == 0:
            reasons.append("No conditional access policies are enabled")
            return False, reasons
        return True, []

    return False, ["Insufficient data to determine conditional access enforcement"]


@engine.assertion("api_key_rotation")
def api_key_rotation(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check API keys older than 90 days.

    Reviews AWS access keys, GCP service account keys, Azure app registrations.
    """
    reasons: list[str] = []

    # AWS IAM access key age
    key_created = (
        detail.get("CreateDate")
        or detail.get("create_date")
        or detail.get("access_key_1_last_rotated")
    )
    if key_created:
        days = _days_since(str(key_created))
        if days is not None and days > 90:
            user = detail.get("UserName") or detail.get("user") or "unknown"
            key_id = detail.get("AccessKeyId") or detail.get("access_key_id") or "?"
            reasons.append(f"Access key {key_id} for {user} is {days} days old (>90)")
            return False, reasons
        if days is not None:
            return True, []

    # GCP service account key
    valid_after = detail.get("validAfterTime") or detail.get("valid_after")
    if valid_after:
        days = _days_since(str(valid_after))
        if days is not None and days > 90:
            sa = detail.get("serviceAccountEmail") or detail.get("name") or "unknown"
            reasons.append(f"GCP service account key for {sa} is {days} days old (>90)")
            return False, reasons
        if days is not None:
            return True, []

    # Azure app credential expiry
    end_date = detail.get("endDateTime") or detail.get("end_date")
    if end_date:
        days = _days_since(str(end_date))
        if days is not None and days > 0:
            app = detail.get("displayName") or detail.get("appDisplayName") or "unknown"
            reasons.append(f"Azure app credential for {app} expired {days} days ago")
            return False, reasons

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list):
        for issue in issues:
            if "key_age" in str(issue).lower() or "rotation" in str(issue).lower():
                reasons.append(f"API key rotation issue: {issue}")
        if reasons:
            return False, reasons

    return True, []


# ---------------------------------------------------------------------------
# Audit & Accountability (AU family)
# ---------------------------------------------------------------------------


@engine.assertion("audit_log_retention_compliant")
def audit_log_retention_compliant(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify logs are retained for required period (1 year minimum).

    Checks S3 lifecycle, CloudWatch retention, SIEM retention.
    """
    reasons: list[str] = []

    # CloudWatch log group retention
    retention_days = (
        detail.get("retentionInDays") or detail.get("retention_days") or detail.get("retention")
    )
    if retention_days is not None:
        if int(retention_days) < 365 and int(retention_days) != 0:  # 0 = never expire
            log_group = detail.get("logGroupName") or detail.get("name") or "unknown"
            reasons.append(f"Log group {log_group} retention is {retention_days} days (<365)")
            return False, reasons
        return True, []

    # S3 lifecycle rules for log buckets
    lifecycle = detail.get("LifecycleConfiguration") or detail.get("lifecycle_rules")
    if isinstance(lifecycle, dict):
        rules = lifecycle.get("Rules", lifecycle.get("rules", []))
        for rule in rules if isinstance(rules, list) else []:
            expiration = rule.get("Expiration", rule.get("expiration", {}))
            if isinstance(expiration, dict):
                exp_days = expiration.get("Days", expiration.get("days", 0))
                if 0 < exp_days < 365:
                    reasons.append(f"S3 lifecycle expires logs after {exp_days} days (<365)")
        if reasons:
            return False, reasons
        if rules:
            return True, []

    # SIEM retention settings
    siem_retention = detail.get("retention_period") or detail.get("retentionPeriod")
    if siem_retention is not None:
        if int(siem_retention) < 365:
            reasons.append(f"SIEM retention is {siem_retention} days (<365)")
            return False, reasons
        return True, []

    return False, ["Insufficient data to determine log retention"]


@engine.assertion("audit_log_tamper_protection")
def audit_log_tamper_protection(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify logs are write-once (S3 Object Lock, immutable storage).

    Checks S3 Object Lock, CloudTrail log file validation, Azure immutable storage.
    """
    reasons: list[str] = []

    # S3 Object Lock
    object_lock = detail.get("ObjectLockConfiguration") or detail.get("object_lock")
    if isinstance(object_lock, dict):
        if object_lock.get("ObjectLockEnabled") != "Enabled":
            bucket = detail.get("Name") or detail.get("bucket_name") or "unknown"
            reasons.append(f"S3 bucket {bucket} does not have Object Lock enabled")
            return False, reasons
        return True, []

    # CloudTrail log file validation
    log_validation = detail.get("LogFileValidationEnabled") or detail.get("log_file_validation")
    if log_validation is not None:
        if log_validation is False:
            trail = detail.get("Name") or detail.get("trail_name") or "unknown"
            reasons.append(f"CloudTrail {trail} log file validation is disabled")
            return False, reasons
        return True, []

    # Azure immutable storage
    immutable = detail.get("immutabilityPolicy") or detail.get("immutable_storage")
    if isinstance(immutable, dict):
        state = immutable.get("state") or immutable.get("status")
        if str(state).lower() not in ("locked", "unlocked"):
            reasons.append("Azure immutable storage policy is not configured")
            return False, reasons
        return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_tamper_protection" in issues:
        reasons.append("Log tamper protection is not enabled")
        return False, reasons

    return False, ["Insufficient data to determine log tamper protection"]


@engine.assertion("centralized_logging_active")
def centralized_logging_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify SIEM receives logs from all sources.

    Checks Splunk, Elastic, Sentinel connector and data ingestion status.
    """
    reasons: list[str] = []

    # SIEM data connector status
    connector_status = (
        detail.get("connectorStatus") or detail.get("connector_status") or detail.get("status")
    )
    connector_name = (
        detail.get("connectorName") or detail.get("connector_name") or detail.get("name")
    )
    if connector_status and connector_name:
        if str(connector_status).lower() not in ("connected", "active", "enabled"):
            reasons.append(f"SIEM connector '{connector_name}' status: {connector_status}")
            return False, reasons
        return True, []

    # Log source count
    total_sources = detail.get("total_sources") or detail.get("totalSources")
    connected_sources = detail.get("connected_sources") or detail.get("connectedSources")
    if total_sources is not None and connected_sources is not None:
        if int(connected_sources) < int(total_sources):
            reasons.append(
                f"Only {connected_sources}/{total_sources} log sources connected to SIEM"
            )
            if int(connected_sources) / max(int(total_sources), 1) < 0.8:
                return False, reasons
        return True, []

    # Last data received
    last_data = detail.get("lastDataReceived") or detail.get("last_event_time")
    if last_data:
        days = _days_since(str(last_data))
        if days is not None and days > 1:
            source = connector_name or "unknown"
            reasons.append(f"No data received from {source} for {days} days")
            return False, reasons
        return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_centralized_logging" in issues:
        reasons.append("Centralized logging is not configured")
        return False, reasons

    return False, ["Insufficient data to determine centralized logging status"]


@engine.assertion("failed_login_monitoring")
def failed_login_monitoring(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify failed login attempts trigger alerts.

    Checks Okta, Entra ID auth logs, SIEM alert rules.
    """
    reasons: list[str] = []

    # Alert rule for failed logins
    alert_enabled = detail.get("alert_enabled") or detail.get("alertEnabled")
    if alert_enabled is not None:
        if alert_enabled is False:
            reasons.append("Failed login monitoring alert is disabled")
            return False, reasons
        return True, []

    # Okta system log event policy
    event_hooks = detail.get("eventHooks") or detail.get("event_hooks", [])
    if isinstance(event_hooks, list):
        login_hooks = [
            h for h in event_hooks if "login" in str(h).lower() or "auth" in str(h).lower()
        ]
        if not login_hooks and event_hooks:
            reasons.append("No event hooks configured for login failures")
            return False, reasons
        if login_hooks:
            return True, []

    # Lockout policy
    lockout_threshold = (
        detail.get("lockout_threshold")
        or detail.get("maxAttempts")
        or detail.get("lockoutThreshold")
    )
    if lockout_threshold is not None:
        if int(lockout_threshold) == 0:
            reasons.append("Account lockout threshold is 0 (no lockout)")
            return False, reasons
        return True, []

    # Detection rule for auth failures
    rule_type = detail.get("rule_type") or detail.get("ruleType")
    if rule_type and "auth" in str(rule_type).lower():
        return True, []

    return False, ["Insufficient data to determine failed login monitoring"]


@engine.assertion("admin_action_logging")
def admin_action_logging(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify admin/privileged actions are logged.

    Checks CloudTrail, Entra ID audit logs, privileged session recording.
    """
    reasons: list[str] = []

    # CloudTrail management events
    event_selectors = detail.get("EventSelectors") or detail.get("event_selectors", [])
    if isinstance(event_selectors, list):
        for sel in event_selectors:
            if not sel.get("IncludeManagementEvents", True):
                reasons.append("CloudTrail management events are not included")
                return False, reasons
        if event_selectors:
            return True, []

    # Session recording enabled (CyberArk PSM)
    session_recording = detail.get("sessionRecording") or detail.get("session_recording")
    if session_recording is not None:
        if session_recording is False or str(session_recording).lower() == "disabled":
            reasons.append("Privileged session recording is disabled")
            return False, reasons
        return True, []

    # Entra ID audit log configuration
    diagnostic_settings = detail.get("diagnosticSettings") or detail.get("diagnostic_settings", [])
    if isinstance(diagnostic_settings, list):
        audit_log_enabled = any("AuditLogs" in str(s.get("logs", [])) for s in diagnostic_settings)
        if not audit_log_enabled and diagnostic_settings:
            reasons.append("Entra ID audit logs are not forwarded to SIEM")
            return False, reasons
        if audit_log_enabled:
            return True, []

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "no_admin_logging" in issues:
        reasons.append("Admin action logging is not configured")
        return False, reasons

    return True, []


@engine.assertion("time_synchronization")
def time_synchronization(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify NTP is configured across infrastructure.

    Checks NTP service status, time drift, chrony/ntpd configuration.
    """
    reasons: list[str] = []

    # NTP status
    ntp_enabled = detail.get("ntp_enabled") or detail.get("ntpEnabled") or detail.get("time_sync")
    if ntp_enabled is not None:
        if ntp_enabled is False or str(ntp_enabled).lower() in ("disabled", "off"):
            host = detail.get("hostname") or detail.get("name") or "unknown"
            reasons.append(f"NTP is not enabled on {host}")
            return False, reasons
        return True, []

    # Time drift
    drift_seconds = (
        detail.get("drift_seconds") or detail.get("timeDrift") or detail.get("clock_skew")
    )
    if drift_seconds is not None:
        if abs(float(drift_seconds)) > 60:
            host = detail.get("hostname") or detail.get("name") or "unknown"
            reasons.append(f"Time drift on {host} is {drift_seconds}s (>60s)")
            return False, reasons
        return True, []

    # AWS VPC — Amazon Time Sync is enabled by default
    if detail.get("VpcId") or detail.get("vpc_id"):
        return True, []

    return True, []


# ---------------------------------------------------------------------------
# Identity & Authentication (IA family)
# ---------------------------------------------------------------------------


@engine.assertion("strong_authentication_required")
def strong_authentication_required(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify password + MFA or passwordless auth is required.

    Checks authentication strength policies across Okta, Entra ID.
    """
    reasons: list[str] = []

    # Entra ID authentication strength
    auth_strength = detail.get("authenticationStrength") or detail.get("authentication_strength")
    if isinstance(auth_strength, dict):
        allowed_combos = auth_strength.get("allowedCombinations", [])
        if isinstance(allowed_combos, list):
            weak = [c for c in allowed_combos if c in ("password", "sms")]
            if weak:
                reasons.append(f"Weak authentication methods allowed: {', '.join(weak)}")
                return False, reasons
        return True, []

    # Okta factor requirements
    detail.get("factorLifetime") or detail.get("factor_lifetime")
    factors_required = detail.get("factors") or detail.get("required_factors", [])
    if isinstance(factors_required, list) and factors_required:
        return True, []

    # Passwordless check
    passwordless = detail.get("passwordless") or detail.get("isPasswordless")
    if passwordless is True:
        return True, []

    # Auth policy requires MFA
    mfa_required = detail.get("mfa_required") or detail.get("requireMfa")
    if mfa_required is True:
        return True, []
    if mfa_required is False:
        policy = detail.get("name") or detail.get("policy_name") or "unknown"
        reasons.append(f"Auth policy '{policy}' does not require MFA")
        return False, reasons

    return False, ["Insufficient data to determine authentication strength"]


@engine.assertion("service_account_managed")
def service_account_managed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check service accounts have no interactive login and keys are rotated.

    Reviews AWS IAM, GCP, Entra ID service principals.
    """
    reasons: list[str] = []

    # Interactive login check
    has_console = (
        detail.get("password_enabled")
        or detail.get("hasConsoleAccess")
        or detail.get("loginEnabled")
    )
    if has_console is True:
        sa = detail.get("user") or detail.get("name") or detail.get("displayName") or "unknown"
        reasons.append(f"Service account {sa} has interactive/console login enabled")

    # Key age
    key_created = (
        detail.get("CreateDate") or detail.get("validAfterTime") or detail.get("key_created")
    )
    if key_created:
        days = _days_since(str(key_created))
        if days is not None and days > 90:
            sa = (
                detail.get("user")
                or detail.get("name")
                or detail.get("serviceAccountEmail")
                or "unknown"
            )
            reasons.append(f"Service account {sa} key is {days} days old (>90 day rotation)")

    # GCP service account key count
    key_count = detail.get("key_count") or detail.get("keys")
    if isinstance(key_count, int) and key_count > 2:
        sa = detail.get("email") or detail.get("name") or "unknown"
        reasons.append(f"Service account {sa} has {key_count} keys (excess keys)")

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("certificate_validity")
def certificate_validity(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check TLS/SSL certificates not expired or expiring within 30 days.

    Reviews ACM, Let's Encrypt, Azure Key Vault certificates.
    """
    reasons: list[str] = []

    # Certificate expiration
    not_after = (
        detail.get("NotAfter")
        or detail.get("not_after")
        or detail.get("expiresOn")
        or detail.get("expiry_date")
        or detail.get("expiration_date")
    )
    if not_after:
        days = _days_since(str(not_after))
        if days is not None:
            if days > 0:
                cert = (
                    detail.get("DomainName")
                    or detail.get("domain")
                    or detail.get("name")
                    or "unknown"
                )
                reasons.append(f"Certificate for {cert} expired {days} days ago")
                return False, reasons
            if days > -30:
                cert = (
                    detail.get("DomainName")
                    or detail.get("domain")
                    or detail.get("name")
                    or "unknown"
                )
                reasons.append(f"Certificate for {cert} expires in {abs(days)} days (<30)")
                return False, reasons
        return True, []

    # ACM certificate status
    cert_status = detail.get("Status") or detail.get("status") or detail.get("certificateStatus")
    if cert_status:
        if str(cert_status).lower() in ("expired", "revoked", "failed", "validation_timed_out"):
            cert = detail.get("DomainName") or detail.get("domain") or "unknown"
            reasons.append(f"Certificate for {cert} status: {cert_status}")
            return False, reasons
        if str(cert_status).lower() in ("issued", "active"):
            return True, []

    return False, ["Insufficient data to determine certificate validity"]


@engine.assertion("default_credentials_removed")
def default_credentials_removed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check for default/factory passwords in device configs.

    Reviews network devices, appliances, database instances.
    """
    reasons: list[str] = []

    # Default credential flags
    has_default = (
        detail.get("default_credentials")
        or detail.get("defaultPassword")
        or detail.get("factory_password")
    )
    if has_default is True:
        device = (
            detail.get("hostname") or detail.get("name") or detail.get("device_name") or "unknown"
        )
        reasons.append(f"Device {device} still has default/factory credentials")
        return False, reasons

    # Scanner finding for default creds
    vuln_type = (
        detail.get("vulnerability_type") or detail.get("pluginName") or detail.get("title") or ""
    )
    if "default" in str(vuln_type).lower() and (
        "password" in str(vuln_type).lower() or "credential" in str(vuln_type).lower()
    ):
        host = detail.get("hostname") or detail.get("host") or detail.get("ip") or "unknown"
        reasons.append(f"Default credentials detected on {host}: {vuln_type}")
        return False, reasons

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list) and "default_credentials" in issues:
        reasons.append("Default credentials found on one or more devices")
        return False, reasons

    return True, []


@engine.assertion("identity_federation_configured")
def identity_federation_configured(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify SSO/SAML/OIDC federation is active.

    Checks identity provider configuration across cloud platforms.
    """
    reasons: list[str] = []

    # SSO enabled
    sso_enabled = (
        detail.get("sso_enabled") or detail.get("ssoEnabled") or detail.get("federationEnabled")
    )
    if sso_enabled is not None:
        if sso_enabled is False:
            app = detail.get("name") or detail.get("app_name") or "unknown"
            reasons.append(f"SSO/federation is not enabled for {app}")
            return False, reasons
        return True, []

    # SAML metadata present
    saml_metadata = (
        detail.get("samlMetadataUrl") or detail.get("saml_metadata") or detail.get("idpMetadata")
    )
    if saml_metadata:
        return True, []

    # AWS IAM Identity Center / SAML provider
    saml_providers = detail.get("SAMLProviderList") or detail.get("saml_providers", [])
    if isinstance(saml_providers, list):
        if len(saml_providers) == 0:
            reasons.append("No SAML identity providers configured in AWS")
            return False, reasons
        return True, []

    # Okta / Entra ID federation
    idp_type = detail.get("type") or detail.get("identityProviderType")
    if idp_type and str(idp_type).upper() in ("SAML2", "OIDC", "SAML_2_0", "OPENID_CONNECT"):
        return True, []

    return False, ["Insufficient data to determine identity federation status"]


# ---------------------------------------------------------------------------
# Incident Response (IR family)
# ---------------------------------------------------------------------------


@engine.assertion("incident_response_tested")
def incident_response_tested(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check for recent IR drill/tabletop exercise (within 1 year).

    Reviews incident response test records, tabletop exercise documentation.
    """
    reasons: list[str] = []

    # Last test date
    last_test = (
        detail.get("last_test_date")
        or detail.get("lastTestDate")
        or detail.get("last_exercise_date")
        or detail.get("exercise_date")
    )
    if last_test:
        days = _days_since(str(last_test))
        if days is not None and days > 365:
            reasons.append(f"IR plan last tested {days} days ago (>365)")
            return False, reasons
        if days is not None:
            return True, []

    # Test status
    test_status = detail.get("test_status") or detail.get("exerciseStatus")
    if test_status:
        if str(test_status).lower() in ("overdue", "not_tested", "expired"):
            reasons.append(f"IR test status: {test_status}")
            return False, reasons
        if str(test_status).lower() in ("completed", "passed"):
            return True, []

    return False, ["Insufficient data to determine IR testing status"]


@engine.assertion("threat_detection_alerts_configured")
def threat_detection_alerts_configured(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify threat detection alerts route to SIEM and PagerDuty/incident management.

    Checks GuardDuty, Defender, SCC alert routing configuration.
    """
    reasons: list[str] = []

    # Alert destination configured
    destinations = (
        detail.get("destinations")
        or detail.get("notification_targets")
        or detail.get("subscribers", [])
    )
    if isinstance(destinations, list):
        if len(destinations) == 0:
            source = detail.get("name") or detail.get("detector_name") or "unknown"
            reasons.append(f"Threat detection source {source} has no alert destinations configured")
            return False, reasons
        return True, []

    # SNS topic for GuardDuty
    sns_topic = detail.get("TopicArn") or detail.get("sns_topic_arn")
    if sns_topic:
        return True, []

    # Event rule for alerts
    event_rule = detail.get("eventRule") or detail.get("event_rule") or detail.get("actionRule")
    if event_rule:
        return True, []

    # Notification enabled
    notifications_enabled = detail.get("notifications_enabled") or detail.get(
        "alertNotificationsEnabled"
    )
    if notifications_enabled is False:
        reasons.append("Threat detection alert notifications are disabled")
        return False, reasons
    if notifications_enabled is True:
        return True, []

    return False, ["Insufficient data to determine threat alert routing"]


@engine.assertion("malware_detection_active")
def malware_detection_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify antivirus/anti-malware is active.

    Checks Sophos, Defender, SentinelOne, CrowdStrike.
    """
    reasons: list[str] = []

    # AV/AM status
    av_status = (
        detail.get("antivirus_status")
        or detail.get("antivirusStatus")
        or detail.get("realTimeProtection")
        or detail.get("malware_protection")
    )
    if av_status is not None:
        if str(av_status).lower() in ("disabled", "off", "inactive", "not_installed"):
            host = (
                detail.get("hostname")
                or detail.get("computerDnsName")
                or detail.get("name")
                or "unknown"
            )
            reasons.append(f"Malware detection is {av_status} on {host}")
            return False, reasons
        return True, []

    # Sophos endpoint shape
    health = detail.get("health") or detail.get("overallHealth")
    if isinstance(health, dict):
        threats = health.get("threats", {})
        if isinstance(threats, dict) and str(threats.get("status", "")).lower() == "bad":
            host = detail.get("hostname") or "unknown"
            reasons.append(f"Sophos threat status is BAD on {host}")
            return False, reasons
        overall = health.get("overall") or health.get("status")
        if overall and str(overall).lower() in ("good", "ok"):
            return True, []

    # Windows Defender status
    am_running = detail.get("AMServiceEnabled") or detail.get("antimalware_service_enabled")
    if am_running is False:
        host = detail.get("hostname") or detail.get("ComputerName") or "unknown"
        reasons.append(f"Antimalware service not running on {host}")
        return False, reasons
    if am_running is True:
        return True, []

    return False, ["Insufficient data to determine malware detection status"]


@engine.assertion("security_incident_tracked")
def security_incident_tracked(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify security incidents have assigned owners and SLAs.

    Checks ServiceNow, Jira, PagerDuty incident records.
    """
    reasons: list[str] = []

    # Incident ownership
    assigned_to = detail.get("assigned_to") or detail.get("assignee") or detail.get("owner")
    if not assigned_to or (isinstance(assigned_to, str) and not assigned_to.strip()):
        incident_id = (
            detail.get("number") or detail.get("incident_id") or detail.get("key") or "unknown"
        )
        priority = detail.get("priority") or detail.get("severity") or "unknown"
        reasons.append(f"Incident {incident_id} (priority: {priority}) has no assigned owner")

    # SLA tracking
    sla_breached = detail.get("sla_breached") or detail.get("slaBreached") or detail.get("breach")
    if sla_breached is True:
        incident_id = (
            detail.get("number") or detail.get("incident_id") or detail.get("key") or "unknown"
        )
        reasons.append(f"Incident {incident_id} has breached its SLA")

    # State check — open incidents without progress
    state = detail.get("state") or detail.get("status") or ""
    if str(state).lower() in ("new", "open") and not assigned_to:
        incident_id = detail.get("number") or detail.get("incident_id") or "unknown"
        created = detail.get("opened_at") or detail.get("created_date") or detail.get("createdAt")
        if created:
            days = _days_since(str(created))
            if days is not None and days > 7:
                reasons.append(f"Incident {incident_id} open and unassigned for {days} days")

    if reasons:
        return False, reasons
    return True, []


# ---------------------------------------------------------------------------
# System Integrity (SI family)
# ---------------------------------------------------------------------------


@engine.assertion("antivirus_definitions_current")
def antivirus_definitions_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify AV definitions updated within 24 hours.

    Checks Sophos, Defender, CrowdStrike sensor versions.
    """
    reasons: list[str] = []

    # Definition update date
    last_update = (
        detail.get("definition_date")
        or detail.get("AntivirusSignatureLastUpdated")
        or detail.get("last_definition_update")
        or detail.get("signatureLastUpdated")
    )
    if last_update:
        days = _days_since(str(last_update))
        if days is not None and days > 1:
            host = detail.get("hostname") or detail.get("ComputerName") or "unknown"
            reasons.append(f"AV definitions on {host} are {days} days old (>1)")
            return False, reasons
        if days is not None:
            return True, []

    # Sensor version check (CrowdStrike)
    sensor_version = detail.get("agent_version") or detail.get("sensorVersion")
    latest_version = detail.get("latest_version") or detail.get("latestSensorVersion")
    if sensor_version and latest_version:
        if sensor_version != latest_version:
            host = detail.get("hostname") or "unknown"
            reasons.append(f"Sensor on {host} is {sensor_version}, latest is {latest_version}")
            return False, reasons
        return True, []

    # Out of date flag
    out_of_date = detail.get("out_of_date") or detail.get("definitionsOutOfDate")
    if out_of_date is True:
        host = detail.get("hostname") or "unknown"
        reasons.append(f"AV definitions out of date on {host}")
        return False, reasons

    return True, []


@engine.assertion("file_integrity_monitoring")
def file_integrity_monitoring(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify FIM is active on critical systems.

    Checks OSSEC, Tripwire, Wazuh, CloudWatch file integrity.
    """
    reasons: list[str] = []

    # FIM status
    fim_enabled = (
        detail.get("fim_enabled")
        or detail.get("fileIntegrityMonitoring")
        or detail.get("integrity_monitoring")
    )
    if fim_enabled is not None:
        if fim_enabled is False or str(fim_enabled).lower() in ("disabled", "off"):
            host = detail.get("hostname") or detail.get("name") or "unknown"
            reasons.append(f"File integrity monitoring is disabled on {host}")
            return False, reasons
        return True, []

    # FIM agent status
    agent_status = detail.get("agent_status") or detail.get("agentStatus")
    if agent_status and "fim" in str(detail.get("agent_type", "")).lower():
        if str(agent_status).lower() in ("disconnected", "offline", "inactive"):
            host = detail.get("hostname") or "unknown"
            reasons.append(f"FIM agent is {agent_status} on {host}")
            return False, reasons
        return True, []

    # FIM policy assigned
    fim_policy = detail.get("fim_policy") or detail.get("integrityMonitoringPolicy")
    if fim_policy:
        return True, []

    return False, ["Insufficient data to determine FIM status"]


@engine.assertion("patch_management_current")
def patch_management_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify OS/app patches applied within SLA.

    30 days for critical, 90 days for high. Checks Jamf, Intune, Qualys, WSUS.
    """
    reasons: list[str] = []

    # Missing patch details
    severity = (
        detail.get("severity")
        or detail.get("patch_severity")
        or detail.get("criticalityLevel")
        or ""
    )
    patch_date = (
        detail.get("release_date") or detail.get("publishedDate") or detail.get("releaseDate")
    )
    if patch_date and severity:
        days = _days_since(str(patch_date))
        if days is not None:
            sev_lower = str(severity).lower()
            if sev_lower == "critical" and days > 30:
                title = detail.get("title") or detail.get("patch_name") or "unknown"
                reasons.append(f"Critical patch '{title}' unpatched for {days} days (SLA: 30)")
                return False, reasons
            if sev_lower == "high" and days > 90:
                title = detail.get("title") or detail.get("patch_name") or "unknown"
                reasons.append(f"High patch '{title}' unpatched for {days} days (SLA: 90)")
                return False, reasons
            return True, []

    # Device patch compliance
    patch_status = detail.get("patch_status") or detail.get("patchComplianceState")
    if patch_status:
        if str(patch_status).lower() in ("non_compliant", "noncompliant", "missing", "failed"):
            host = detail.get("hostname") or detail.get("deviceName") or "unknown"
            reasons.append(f"Device {host} patch status: {patch_status}")
            return False, reasons
        return True, []

    # Missing patches count
    missing_count = detail.get("missing_patches") or detail.get("missingPatchCount")
    if missing_count is not None:
        if int(missing_count) > 0:
            host = detail.get("hostname") or detail.get("name") or "unknown"
            reasons.append(f"Device {host} has {missing_count} missing patches")
            return False, reasons
        return True, []

    return True, []


@engine.assertion("software_whitelist_enforced")
def software_whitelist_enforced(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify application control/whitelisting is active.

    Checks Windows AppLocker, macOS Gatekeeper, endpoint policies.
    """
    reasons: list[str] = []

    # Application control status
    app_control = (
        detail.get("application_control") or detail.get("appControl") or detail.get("appLocker")
    )
    if app_control is not None:
        if isinstance(app_control, dict):
            enabled = app_control.get("enabled", app_control.get("isEnabled", False))
            if not enabled:
                host = detail.get("hostname") or detail.get("name") or "unknown"
                reasons.append(f"Application control is disabled on {host}")
                return False, reasons
            return True, []
        if app_control is False or str(app_control).lower() in ("disabled", "off"):
            host = detail.get("hostname") or detail.get("name") or "unknown"
            reasons.append(f"Application control is disabled on {host}")
            return False, reasons
        return True, []

    # Unauthorized software detected
    unauthorized = detail.get("unauthorized_software") or detail.get("blockedApps", [])
    if isinstance(unauthorized, list) and unauthorized:
        host = detail.get("hostname") or "unknown"
        reasons.append(f"Unauthorized software detected on {host}: {len(unauthorized)} app(s)")
        return False, reasons

    return False, ["Insufficient data to determine application control status"]


@engine.assertion("spam_protection_active")
def spam_protection_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify email security is active.

    Checks Proofpoint, Abnormal Security, Microsoft Defender for Office 365.
    """
    reasons: list[str] = []

    # Email security status
    email_security = (
        detail.get("email_security") or detail.get("emailSecurity") or detail.get("antiSpam")
    )
    if email_security is not None:
        if isinstance(email_security, dict):
            enabled = email_security.get("enabled", email_security.get("isEnabled", False))
            if not enabled:
                reasons.append("Email security/anti-spam is disabled")
                return False, reasons
            return True, []
        if email_security is False or str(email_security).lower() in ("disabled", "off"):
            reasons.append("Email security/anti-spam is disabled")
            return False, reasons
        return True, []

    # MX records pointing to security gateway
    mx_records = detail.get("mx_records") or detail.get("mxRecords", [])
    if isinstance(mx_records, list) and mx_records:
        security_gateways = {
            "pphosted.com",
            "mimecast.com",
            "google.com",
            "outlook.com",
            "barracuda",
        }
        has_gateway = any(
            any(gw in str(mx).lower() for gw in security_gateways) for mx in mx_records
        )
        if has_gateway:
            return True, []

    # DMARC/SPF/DKIM
    dmarc = detail.get("dmarc") or detail.get("dmarcPolicy")
    spf = detail.get("spf") or detail.get("spfRecord")
    if dmarc and spf:
        return True, []

    return False, ["Insufficient data to determine email security status"]


@engine.assertion("input_validation_enforced")
def input_validation_enforced(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check for SQL injection, XSS findings from code scanners.

    If critical injection/XSS vulnerabilities exist, fail. Checks Checkmarx, SonarQube.
    """
    reasons: list[str] = []

    # Code scan vulnerability type
    vuln_type = (
        detail.get("vulnerability_type") or detail.get("category") or detail.get("cweId") or ""
    )
    severity = detail.get("severity") or detail.get("issue_severity") or ""
    injection_types = {
        "sql_injection",
        "sqli",
        "xss",
        "cross_site_scripting",
        "command_injection",
        "ldap_injection",
        "xpath_injection",
        "cwe-79",
        "cwe-89",
        "cwe-78",
        "cwe-90",
    }
    vuln_lower = str(vuln_type).lower().replace("-", "_").replace(" ", "_")
    if any(it in vuln_lower for it in injection_types):
        if str(severity).lower() in ("critical", "high"):
            title = detail.get("title") or detail.get("name") or vuln_type
            reasons.append(f"Critical input validation vulnerability: {title}")
            return False, reasons

    # SAST scan results summary
    critical_count = detail.get("critical_injection_count") or detail.get("criticalInjectionVulns")
    if critical_count is not None and int(critical_count) > 0:
        reasons.append(f"{critical_count} critical injection vulnerabilities in codebase")
        return False, reasons

    # Issues
    issues = detail.get("issues", [])
    if isinstance(issues, list):
        for issue in issues:
            if "injection" in str(issue).lower() or "xss" in str(issue).lower():
                reasons.append(f"Input validation issue: {issue}")
        if reasons:
            return False, reasons

    return True, []


# ---------------------------------------------------------------------------
# Configuration Management (CM family)
# ---------------------------------------------------------------------------


@engine.assertion("baseline_configuration_documented")
def baseline_configuration_documented(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify system baselines exist and are current.

    Checks for documented configuration baselines, CIS benchmarks applied.
    """
    reasons: list[str] = []

    # Baseline exists
    baseline = (
        detail.get("baseline")
        or detail.get("configuration_baseline")
        or detail.get("hardening_standard")
    )
    if baseline is not None:
        if isinstance(baseline, dict):
            if not baseline.get("documented", True):
                system = detail.get("name") or detail.get("system_name") or "unknown"
                reasons.append(f"System {system} has no documented baseline configuration")
                return False, reasons
            last_updated = baseline.get("last_updated") or baseline.get("updated_at")
            if last_updated:
                days = _days_since(str(last_updated))
                if days is not None and days > 365:
                    reasons.append(f"Baseline last updated {days} days ago (>365)")
                    return False, reasons
            return True, []
        return True, []

    # CIS benchmark score
    cis_score = (
        detail.get("cis_score") or detail.get("benchmark_score") or detail.get("complianceScore")
    )
    if cis_score is not None:
        if float(cis_score) < 70:
            system = detail.get("name") or detail.get("hostname") or "unknown"
            reasons.append(f"System {system} CIS benchmark score is {cis_score}% (<70%)")
            return False, reasons
        return True, []

    return False, ["Insufficient data to verify baseline configuration"]


@engine.assertion("configuration_change_tracked")
def configuration_change_tracked(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify all changes go through change management.

    Checks ServiceNow change records, Git commits, deployment records.
    """
    reasons: list[str] = []

    # Change has ticket/approval
    change_ticket = (
        detail.get("change_ticket") or detail.get("change_number") or detail.get("changeRequestId")
    )
    if detail.get("deployment") or detail.get("config_change"):
        if not change_ticket:
            resource = detail.get("resource") or detail.get("name") or "unknown"
            reasons.append(f"Configuration change to {resource} has no change ticket")
            return False, reasons
        return True, []

    # Unauthorized change detection
    unauthorized = detail.get("unauthorized_change") or detail.get("drift_detected")
    if unauthorized is True:
        resource = detail.get("resource") or detail.get("name") or "unknown"
        reasons.append(f"Unauthorized configuration change detected on {resource}")
        return False, reasons

    # AWS Config compliance
    compliance_type = detail.get("ComplianceType") or detail.get("compliance_type")
    if compliance_type:
        if str(compliance_type).upper() == "NON_COMPLIANT":
            rule = detail.get("ConfigRuleName") or detail.get("config_rule") or "unknown"
            resource = detail.get("ResourceId") or detail.get("resource_id") or "unknown"
            reasons.append(f"Config rule {rule} non-compliant for {resource}")
            return False, reasons
        return True, []

    return True, []


@engine.assertion("unauthorized_software_blocked")
def unauthorized_software_blocked(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify only approved software runs on endpoints.

    Checks software inventory against approved list.
    """
    reasons: list[str] = []

    # Unapproved software found
    unapproved = (
        detail.get("unapproved_software")
        or detail.get("unauthorized_apps")
        or detail.get("blockedApplications", [])
    )
    if isinstance(unapproved, list) and unapproved:
        host = detail.get("hostname") or detail.get("deviceName") or "unknown"
        reasons.append(f"Unapproved software on {host}: {len(unapproved)} application(s)")
        return False, reasons

    # Software restriction policy
    srp_enabled = detail.get("software_restriction_enabled") or detail.get("appControlEnabled")
    if srp_enabled is False:
        host = detail.get("hostname") or detail.get("name") or "unknown"
        reasons.append(f"Software restriction policies not enforced on {host}")
        return False, reasons
    if srp_enabled is True:
        return True, []

    # Inventory compliance
    compliant = detail.get("software_compliant") or detail.get("inventoryCompliant")
    if compliant is False:
        host = detail.get("hostname") or detail.get("name") or "unknown"
        reasons.append(f"Software inventory on {host} is non-compliant")
        return False, reasons
    if compliant is True:
        return True, []

    return False, ["Insufficient data to determine software compliance"]


@engine.assertion("container_image_signed")
def container_image_signed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify container images are signed and scanned.

    Checks Kubernetes admission policies, image scanning results.
    """
    reasons: list[str] = []

    # Image signature
    signed = detail.get("signed") or detail.get("imageSigned") or detail.get("cosign_verified")
    if signed is False:
        image = (
            detail.get("image") or detail.get("imageName") or detail.get("repository") or "unknown"
        )
        reasons.append(f"Container image {image} is not signed")

    # Image scan results
    scan_status = detail.get("scan_status") or detail.get("scanStatus")
    if scan_status and str(scan_status).lower() in ("failed", "not_scanned"):
        image = detail.get("image") or detail.get("imageName") or "unknown"
        reasons.append(f"Container image {image} scan status: {scan_status}")

    # Critical vulns in image
    critical_vulns = detail.get("critical_vulnerabilities") or detail.get("criticalCount")
    if critical_vulns is not None and int(critical_vulns) > 0:
        image = detail.get("image") or detail.get("imageName") or "unknown"
        reasons.append(f"Container image {image} has {critical_vulns} critical vulnerabilities")

    # Admission policy
    admission_policy = detail.get("admission_policy") or detail.get("admissionControl")
    if isinstance(admission_policy, dict):
        if not admission_policy.get("enabled", True):
            reasons.append("Container admission control policy is disabled")

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("infrastructure_as_code_validated")
def infrastructure_as_code_validated(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify IaC (Terraform) passes validation before deploy.

    Checks CI/CD pipeline validation gates, policy checks.
    """
    reasons: list[str] = []

    # IaC validation status
    validation = (
        detail.get("validation_status") or detail.get("iacValidation") or detail.get("planStatus")
    )
    if validation:
        if str(validation).lower() in ("failed", "error", "rejected"):
            workspace = detail.get("workspace") or detail.get("name") or "unknown"
            reasons.append(f"IaC validation failed for workspace {workspace}")
            return False, reasons
        return True, []

    # Policy check results
    policy_check = (
        detail.get("policy_check") or detail.get("sentinelPolicyCheck") or detail.get("opaResult")
    )
    if isinstance(policy_check, dict):
        passed = policy_check.get("passed", policy_check.get("result", True))
        if not passed:
            reasons.append(f"IaC policy check failed: {policy_check.get('message', 'unknown')}")
            return False, reasons
        return True, []

    # Drift detection
    drift = detail.get("drift_detected") or detail.get("resourceDrift")
    if drift is True:
        workspace = detail.get("workspace") or detail.get("name") or "unknown"
        reasons.append(f"Infrastructure drift detected in {workspace}")
        return False, reasons

    return True, []


# ---------------------------------------------------------------------------
# Contingency Planning (CP family)
# ---------------------------------------------------------------------------


@engine.assertion("backup_encryption_enabled")
def backup_encryption_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify backups are encrypted.

    Checks Veeam, AWS Backup, Azure Backup encryption settings.
    """
    reasons: list[str] = []

    # Backup encryption
    encrypted = (
        detail.get("encrypted") or detail.get("isEncrypted") or detail.get("encryption_enabled")
    )
    if encrypted is not None:
        if encrypted is False:
            job = (
                detail.get("job_name")
                or detail.get("name")
                or detail.get("BackupVaultName")
                or "unknown"
            )
            reasons.append(f"Backup {job} is not encrypted")
            return False, reasons
        return True, []

    # AWS Backup vault encryption
    encryption_key = detail.get("EncryptionKeyArn") or detail.get("encryption_key_arn")
    if encryption_key:
        return True, []
    vault_name = detail.get("BackupVaultName") or detail.get("vault_name")
    if vault_name and not encryption_key:
        reasons.append(f"Backup vault {vault_name} has no encryption key configured")
        return False, reasons

    # Veeam encryption
    encryption_options = detail.get("encryptionOptions") or detail.get("encryption_options")
    if isinstance(encryption_options, dict):
        if not encryption_options.get("enabled", False):
            job = detail.get("name") or "unknown"
            reasons.append(f"Veeam backup job {job} encryption is disabled")
            return False, reasons
        return True, []

    return False, ["Insufficient data to determine backup encryption"]


@engine.assertion("disaster_recovery_tested")
def disaster_recovery_tested(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check for recent DR test (within 1 year).

    Reviews DR test records and recovery exercise documentation.
    """
    reasons: list[str] = []

    # Last DR test date
    last_test = (
        detail.get("last_dr_test")
        or detail.get("lastDrTest")
        or detail.get("last_recovery_test")
        or detail.get("recovery_test_date")
    )
    if last_test:
        days = _days_since(str(last_test))
        if days is not None and days > 365:
            reasons.append(f"Disaster recovery plan last tested {days} days ago (>365)")
            return False, reasons
        if days is not None:
            return True, []

    # DR test status
    dr_status = detail.get("dr_test_status") or detail.get("recoveryTestStatus")
    if dr_status:
        if str(dr_status).lower() in ("overdue", "not_tested", "failed"):
            reasons.append(f"DR test status: {dr_status}")
            return False, reasons
        if str(dr_status).lower() in ("completed", "passed", "successful"):
            return True, []

    # Recovery test results
    rto_met = detail.get("rto_met") or detail.get("rtoAchieved")
    rpo_met = detail.get("rpo_met") or detail.get("rpoAchieved")
    if rto_met is False:
        reasons.append("Recovery Time Objective (RTO) was not met in last DR test")
    if rpo_met is False:
        reasons.append("Recovery Point Objective (RPO) was not met in last DR test")

    if reasons:
        return False, reasons
    return False, ["Insufficient data to determine DR testing status"]


@engine.assertion("backup_offsite_stored")
def backup_offsite_stored(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify backups stored in different region/location.

    Checks cross-region replication, offsite storage configuration.
    """
    reasons: list[str] = []

    # Cross-region replication
    cross_region = (
        detail.get("cross_region_replication")
        or detail.get("crossRegionCopy")
        or detail.get("replication_enabled")
    )
    if cross_region is not None:
        if cross_region is False:
            job = detail.get("name") or detail.get("job_name") or "unknown"
            reasons.append(f"Backup {job} has no cross-region/offsite copy")
            return False, reasons
        return True, []

    # Backup copy target
    copy_target = (
        detail.get("copy_target_region")
        or detail.get("destinationVault")
        or detail.get("offsite_location")
    )
    if copy_target:
        return True, []

    # Source and destination region comparison
    source_region = detail.get("source_region") or detail.get("region")
    dest_region = detail.get("destination_region") or detail.get("targetRegion")
    if source_region and dest_region:
        if source_region == dest_region:
            reasons.append(
                f"Backup source and destination are in the same region ({source_region})"
            )
            return False, reasons
        return True, []

    return False, ["Insufficient data to verify offsite backup storage"]


@engine.assertion("recovery_time_achievable")
def recovery_time_achievable(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify RTO/RPO are documented and tested.

    Checks business continuity documentation and test results.
    """
    reasons: list[str] = []

    # RTO/RPO documented
    rto = detail.get("rto") or detail.get("recovery_time_objective")
    rpo = detail.get("rpo") or detail.get("recovery_point_objective")
    if not rto and not rpo:
        system = detail.get("name") or detail.get("system_name") or "unknown"
        reasons.append(f"System {system} has no documented RTO/RPO")
        return False, reasons

    # Tested vs target
    actual_rto = detail.get("actual_rto") or detail.get("tested_recovery_time")
    if rto and actual_rto:
        if float(actual_rto) > float(rto):
            reasons.append(f"Tested RTO ({actual_rto}h) exceeds target ({rto}h)")
            return False, reasons

    actual_rpo = detail.get("actual_rpo") or detail.get("tested_recovery_point")
    if rpo and actual_rpo:
        if float(actual_rpo) > float(rpo):
            reasons.append(f"Tested RPO ({actual_rpo}h) exceeds target ({rpo}h)")
            return False, reasons

    if reasons:
        return False, reasons
    return True, []


# ---------------------------------------------------------------------------
# Risk Assessment (RA family)
# ---------------------------------------------------------------------------


@engine.assertion("vulnerability_remediation_sla")
def vulnerability_remediation_sla(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Check critical vulns fixed within 15 days, high within 30.

    Reviews vulnerability aging across Tenable, Qualys, Wiz.
    """
    reasons: list[str] = []

    severity = (
        detail.get("severity") or detail.get("risk_rating") or detail.get("criticalityLevel") or ""
    )
    found_date = (
        detail.get("first_found")
        or detail.get("firstDetected")
        or detail.get("found_date")
        or detail.get("createdAt")
    )
    fixed_date = (
        detail.get("fixed_date") or detail.get("resolvedAt") or detail.get("remediated_date")
    )

    if found_date and not fixed_date:
        days = _days_since(str(found_date))
        if days is not None:
            sev_lower = str(severity).lower()
            if sev_lower == "critical" and days > 15:
                vuln = (
                    detail.get("title")
                    or detail.get("plugin_name")
                    or detail.get("cve")
                    or "unknown"
                )
                reasons.append(f"Critical vuln '{vuln}' open for {days} days (SLA: 15)")
                return False, reasons
            if sev_lower == "high" and days > 30:
                vuln = (
                    detail.get("title")
                    or detail.get("plugin_name")
                    or detail.get("cve")
                    or "unknown"
                )
                reasons.append(f"High vuln '{vuln}' open for {days} days (SLA: 30)")
                return False, reasons
            if sev_lower == "medium" and days > 90:
                vuln = (
                    detail.get("title")
                    or detail.get("plugin_name")
                    or detail.get("cve")
                    or "unknown"
                )
                reasons.append(f"Medium vuln '{vuln}' open for {days} days (SLA: 90)")
                return False, reasons
            return True, []

    # Summary shape — overdue vulnerabilities
    overdue_count = detail.get("overdue_count") or detail.get("slaBreachedCount")
    if overdue_count is not None and int(overdue_count) > 0:
        reasons.append(f"{overdue_count} vulnerabilities have breached remediation SLA")
        return False, reasons

    return True, []


@engine.assertion("risk_assessment_current")
def risk_assessment_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify risk assessment performed within 1 year.

    Reviews risk register and assessment documentation.
    """
    reasons: list[str] = []

    # Last assessment date
    last_assessment = (
        detail.get("last_assessment_date")
        or detail.get("lastAssessment")
        or detail.get("assessment_date")
        or detail.get("completed_date")
    )
    if last_assessment:
        days = _days_since(str(last_assessment))
        if days is not None and days > 365:
            reasons.append(f"Risk assessment last performed {days} days ago (>365)")
            return False, reasons
        if days is not None:
            return True, []

    # Assessment status
    status = detail.get("status") or detail.get("assessment_status")
    if status:
        if str(status).lower() in ("overdue", "expired", "not_completed"):
            reasons.append(f"Risk assessment status: {status}")
            return False, reasons
        if str(status).lower() in ("completed", "current", "active"):
            return True, []

    return False, ["Insufficient data to determine risk assessment currency"]


@engine.assertion("penetration_test_current")
def penetration_test_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify penetration test performed within 1 year.

    Reviews pentest records and remediation status.
    """
    reasons: list[str] = []

    # Last pentest date
    last_test = (
        detail.get("last_pentest_date")
        or detail.get("lastPentestDate")
        or detail.get("test_date")
        or detail.get("completed_date")
    )
    if last_test:
        days = _days_since(str(last_test))
        if days is not None and days > 365:
            reasons.append(f"Penetration test last performed {days} days ago (>365)")
            return False, reasons
        if days is not None:
            return True, []

    # Open findings from pentest
    open_critical = detail.get("open_critical_findings") or detail.get("unremediated_critical")
    if open_critical is not None and int(open_critical) > 0:
        reasons.append(f"Penetration test has {open_critical} open critical findings")
        return False, reasons

    # Status
    status = detail.get("status") or detail.get("pentest_status")
    if status:
        if str(status).lower() in ("overdue", "not_scheduled"):
            reasons.append(f"Penetration test status: {status}")
            return False, reasons
        if str(status).lower() in ("completed", "passed", "scheduled"):
            return True, []

    return False, ["Insufficient data to determine penetration test currency"]


# ---------------------------------------------------------------------------
# Personnel Security (PS family)
# ---------------------------------------------------------------------------


@engine.assertion("termination_access_revoked")
def termination_access_revoked(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify terminated employees have access revoked within 24 hours.

    Cross-references BambooHR/Workday termination with Okta/Entra ID.
    """
    reasons: list[str] = []

    # Termination date vs account status
    termination_date = (
        detail.get("termination_date") or detail.get("terminationDate") or detail.get("end_date")
    )
    account_status = (
        detail.get("account_status") or detail.get("accountEnabled") or detail.get("okta_status")
    )

    if termination_date:
        days_since_term = _days_since(str(termination_date))
        if days_since_term is not None and days_since_term > 0:
            # Employee terminated — check if access is revoked
            if account_status and str(account_status).lower() in (
                "active",
                "true",
                "enabled",
                "provisioned",
            ):
                employee = (
                    detail.get("employee_name")
                    or detail.get("name")
                    or detail.get("email")
                    or "unknown"
                )
                reasons.append(
                    f"Terminated employee {employee} still has active access "
                    f"({days_since_term} days since termination)"
                )
                return False, reasons
            return True, []

    # Deprovisioning gap
    deprovisioned_date = detail.get("deprovisioned_date") or detail.get("deprovisionedAt")
    if termination_date and deprovisioned_date:
        term_days = _days_since(str(termination_date))
        deprov_days = _days_since(str(deprovisioned_date))
        if term_days is not None and deprov_days is not None:
            gap = term_days - deprov_days
            if gap > 1:
                employee = detail.get("employee_name") or detail.get("name") or "unknown"
                reasons.append(
                    f"Employee {employee} access revoked {gap} days after termination (>1 day)"
                )
                return False, reasons

    return True, []


@engine.assertion("role_change_access_reviewed")
def role_change_access_reviewed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify access is reviewed when roles change.

    Checks for access recertification after job transfers.
    """
    reasons: list[str] = []

    # Role change detected
    role_change = detail.get("role_change") or detail.get("jobChange") or detail.get("transfer")
    if role_change is True or isinstance(role_change, dict):
        review_completed = detail.get("access_review_completed") or detail.get(
            "recertificationCompleted"
        )
        if review_completed is False or review_completed is None:
            employee = detail.get("employee_name") or detail.get("name") or "unknown"
            new_role = detail.get("new_role") or detail.get("newTitle") or "unknown"
            reasons.append(f"Employee {employee} changed to role {new_role} without access review")
            return False, reasons
        return True, []

    # Mover certification status
    cert_status = detail.get("mover_certification_status") or detail.get("transferReview")
    if cert_status:
        if str(cert_status).lower() in ("pending", "overdue", "not_started"):
            employee = detail.get("employee_name") or detail.get("name") or "unknown"
            reasons.append(f"Mover access review for {employee} is {cert_status}")
            return False, reasons
        return True, []

    return True, []


@engine.assertion("security_clearance_verified")
def security_clearance_verified(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify clearance status for roles requiring it.

    Checks clearance records against role requirements.
    """
    reasons: list[str] = []

    # Clearance required but not verified
    clearance_required = detail.get("clearance_required") or detail.get("requiresClearance")
    clearance_status = detail.get("clearance_status") or detail.get("clearanceLevel")
    if clearance_required is True:
        if not clearance_status or str(clearance_status).lower() in (
            "none",
            "expired",
            "revoked",
            "pending",
        ):
            employee = detail.get("employee_name") or detail.get("name") or "unknown"
            reasons.append(
                f"Employee {employee} requires clearance but status is: {clearance_status or 'none'}"
            )
            return False, reasons

    # Clearance expiry
    clearance_expiry = detail.get("clearance_expiry") or detail.get("clearanceExpiryDate")
    if clearance_expiry:
        days = _days_since(str(clearance_expiry))
        if days is not None and days > 0:
            employee = detail.get("employee_name") or detail.get("name") or "unknown"
            reasons.append(f"Employee {employee} clearance expired {days} days ago")
            return False, reasons

    return True, []


# ---------------------------------------------------------------------------
# Physical Security (PE family)
# ---------------------------------------------------------------------------


@engine.assertion("physical_access_controlled")
def physical_access_controlled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify badge/door access systems are active.

    Checks Verkada, access control system status.
    """
    reasons: list[str] = []

    # Access control system status
    system_status = (
        detail.get("system_status") or detail.get("controllerStatus") or detail.get("status")
    )
    if system_status:
        if str(system_status).lower() in ("offline", "error", "disconnected", "tampered"):
            location = (
                detail.get("location") or detail.get("door_name") or detail.get("name") or "unknown"
            )
            reasons.append(f"Physical access control at {location} is {system_status}")
            return False, reasons

    # Door forced/held open
    door_alarm = (
        detail.get("door_forced") or detail.get("door_held_open") or detail.get("alarmActive")
    )
    if door_alarm is True:
        location = detail.get("location") or detail.get("door_name") or "unknown"
        reasons.append(f"Physical security alarm at {location}: door forced or held open")
        return False, reasons

    # Badge reader health
    reader_status = detail.get("reader_status") or detail.get("readerHealth")
    if reader_status and str(reader_status).lower() in ("offline", "fault"):
        location = detail.get("location") or detail.get("name") or "unknown"
        reasons.append(f"Badge reader at {location} is {reader_status}")
        return False, reasons

    if system_status and str(system_status).lower() in ("online", "active", "normal"):
        return True, []

    return True, []


@engine.assertion("visitor_access_logged")
def visitor_access_logged(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify visitor logs exist and are maintained.

    Checks visitor management system records.
    """
    reasons: list[str] = []

    # Visitor logging enabled
    visitor_logging = (
        detail.get("visitor_logging")
        or detail.get("visitorManagement")
        or detail.get("visitor_system")
    )
    if visitor_logging is not None:
        if visitor_logging is False or str(visitor_logging).lower() in ("disabled", "inactive"):
            location = detail.get("location") or detail.get("site_name") or "unknown"
            reasons.append(f"Visitor logging is not active at {location}")
            return False, reasons
        return True, []

    # Visitor log entries
    log_entries = (
        detail.get("visitor_entries") or detail.get("logEntries") or detail.get("visitor_count")
    )
    if isinstance(log_entries, list) and log_entries:
        # Check for missing sign-outs
        unsigned = [e for e in log_entries if not e.get("sign_out_time") and not e.get("signedOut")]
        if unsigned:
            reasons.append(f"{len(unsigned)} visitors not signed out")
            return False, reasons
        return True, []

    return True, []


# ---------------------------------------------------------------------------
# Supply Chain (SR family)
# ---------------------------------------------------------------------------


@engine.assertion("vendor_risk_assessed")
def vendor_risk_assessed(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify critical vendors have current risk assessments.

    Checks SecurityScorecard, vendor risk management records.
    """
    reasons: list[str] = []

    # Vendor risk assessment date
    last_assessment = (
        detail.get("last_assessment") or detail.get("lastAssessment") or detail.get("review_date")
    )
    if last_assessment:
        days = _days_since(str(last_assessment))
        if days is not None and days > 365:
            vendor = (
                detail.get("vendor_name")
                or detail.get("name")
                or detail.get("company")
                or "unknown"
            )
            reasons.append(f"Vendor {vendor} last assessed {days} days ago (>365)")
            return False, reasons
        if days is not None:
            return True, []

    # SecurityScorecard grade
    score = detail.get("score") or detail.get("securityScore") or detail.get("overallGrade")
    if score is not None:
        if isinstance(score, (int, float)) and score < 65:
            vendor = detail.get("vendor_name") or detail.get("name") or "unknown"
            reasons.append(f"Vendor {vendor} security score is {score} (<65)")
            return False, reasons
        if isinstance(score, str) and score.upper() in ("D", "F"):
            vendor = detail.get("vendor_name") or detail.get("name") or "unknown"
            reasons.append(f"Vendor {vendor} security grade is {score}")
            return False, reasons
        return True, []

    # Vendor criticality without assessment
    criticality = detail.get("criticality") or detail.get("tier") or detail.get("risk_tier")
    if criticality and str(criticality).lower() in ("critical", "high", "tier1", "tier_1"):
        if not last_assessment:
            vendor = detail.get("vendor_name") or detail.get("name") or "unknown"
            reasons.append(f"Critical vendor {vendor} has no risk assessment on record")
            return False, reasons

    return True, []


@engine.assertion("third_party_sla_monitored")
def third_party_sla_monitored(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify vendor SLAs are tracked and met.

    Checks SLA performance metrics and breach tracking.
    """
    reasons: list[str] = []

    # SLA breach
    sla_breached = (
        detail.get("sla_breached") or detail.get("slaBreached") or detail.get("breach_detected")
    )
    if sla_breached is True:
        vendor = detail.get("vendor_name") or detail.get("name") or "unknown"
        sla_type = detail.get("sla_type") or detail.get("metric") or "unspecified"
        reasons.append(f"Vendor {vendor} SLA breach: {sla_type}")
        return False, reasons

    # SLA monitoring configured
    sla_monitoring = detail.get("sla_monitoring") or detail.get("monitoringEnabled")
    if sla_monitoring is False:
        vendor = detail.get("vendor_name") or detail.get("name") or "unknown"
        reasons.append(f"SLA monitoring not configured for vendor {vendor}")
        return False, reasons

    # Uptime SLA
    uptime = detail.get("uptime_pct") or detail.get("availability")
    target = detail.get("target_uptime") or detail.get("sla_target") or 99.9
    if uptime is not None:
        if float(uptime) < float(target):
            vendor = detail.get("vendor_name") or detail.get("name") or "unknown"
            reasons.append(f"Vendor {vendor} uptime {uptime}% below SLA target {target}%")
            return False, reasons
        return True, []

    return True, []


# ---------------------------------------------------------------------------
# Privacy (PT family)
# ---------------------------------------------------------------------------


@engine.assertion("data_minimization_verified")
def data_minimization_verified(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify data collection is limited to necessary fields.

    Checks data classification, collection scope, retention policies.
    """
    reasons: list[str] = []

    # Excessive data collection
    excessive_fields = detail.get("excessive_fields") or detail.get("unnecessaryDataFields", [])
    if isinstance(excessive_fields, list) and excessive_fields:
        system = detail.get("system_name") or detail.get("name") or "unknown"
        reasons.append(
            f"System {system} collects {len(excessive_fields)} unnecessary data field(s)"
        )
        return False, reasons

    # Data classification
    classification = detail.get("data_classification") or detail.get("classification")
    purpose = detail.get("collection_purpose") or detail.get("purpose")
    if classification and not purpose:
        system = detail.get("system_name") or detail.get("name") or "unknown"
        reasons.append(f"System {system} has classified data without documented purpose")
        return False, reasons

    # Retention policy
    has_retention = detail.get("retention_policy") or detail.get("retentionPolicy")
    if has_retention is False:
        system = detail.get("system_name") or detail.get("name") or "unknown"
        reasons.append(f"System {system} has no data retention policy")
        return False, reasons

    # Data minimization review
    review_status = detail.get("minimization_review") or detail.get("dataMinimizationReview")
    if review_status and str(review_status).lower() in ("overdue", "not_completed", "failed"):
        reasons.append(f"Data minimization review status: {review_status}")
        return False, reasons

    return True, []


@engine.assertion("consent_mechanism_active")
def consent_mechanism_active(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify consent collection is active for PII processing.

    Checks consent management platforms, cookie consent, privacy notices.
    """
    reasons: list[str] = []

    # Consent mechanism status
    consent_enabled = detail.get("consent_enabled") or detail.get("consentMechanismActive")
    if consent_enabled is not None:
        if consent_enabled is False:
            system = detail.get("system_name") or detail.get("name") or "unknown"
            reasons.append(f"Consent mechanism is not active for {system}")
            return False, reasons
        return True, []

    # Cookie consent banner
    cookie_consent = detail.get("cookie_consent") or detail.get("cookieBanner")
    if cookie_consent is not None:
        if cookie_consent is False or str(cookie_consent).lower() in ("disabled", "missing"):
            domain = detail.get("domain") or detail.get("url") or "unknown"
            reasons.append(f"Cookie consent banner missing on {domain}")
            return False, reasons
        return True, []

    # Privacy notice
    privacy_notice = detail.get("privacy_notice") or detail.get("privacyPolicy")
    if privacy_notice is not None:
        if isinstance(privacy_notice, dict):
            if not privacy_notice.get("published", True):
                reasons.append("Privacy notice is not published")
                return False, reasons
            last_updated = privacy_notice.get("last_updated") or privacy_notice.get("updatedAt")
            if last_updated:
                days = _days_since(str(last_updated))
                if days is not None and days > 365:
                    reasons.append(f"Privacy notice last updated {days} days ago (>365)")
                    return False, reasons
        return True, []

    return False, ["Insufficient data to determine consent mechanism status"]


# ---------------------------------------------------------------------------
# AI Governance
# ---------------------------------------------------------------------------


@engine.assertion("ai_model_inventory_current")
def ai_model_inventory_current(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify AI models are inventoried and approved.

    Checks MLflow, model registries, AI governance records.
    """
    reasons: list[str] = []

    # Model approval status
    approval = detail.get("approval_status") or detail.get("modelApproval") or detail.get("stage")
    if approval:
        if str(approval).lower() in ("rejected", "unapproved", "pending", "archived"):
            model = detail.get("model_name") or detail.get("name") or "unknown"
            reasons.append(f"AI model {model} approval status: {approval}")
            return False, reasons

    # Model inventory
    registered = detail.get("registered") or detail.get("in_inventory") or detail.get("inventoried")
    if registered is False:
        model = detail.get("model_name") or detail.get("name") or "unknown"
        reasons.append(f"AI model {model} is not registered in model inventory")
        return False, reasons

    # Risk classification
    risk_level = detail.get("risk_level") or detail.get("aiRiskClassification")
    if risk_level and str(risk_level).lower() in ("high", "unacceptable"):
        impact_assessment = detail.get("impact_assessment") or detail.get("riskAssessment")
        if not impact_assessment:
            model = detail.get("model_name") or detail.get("name") or "unknown"
            reasons.append(f"High-risk AI model {model} has no impact assessment")
            return False, reasons

    # Model documentation
    documentation = (
        detail.get("model_card") or detail.get("documentation") or detail.get("modelCard")
    )
    if documentation is False:
        model = detail.get("model_name") or detail.get("name") or "unknown"
        reasons.append(f"AI model {model} has no model card/documentation")
        return False, reasons

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("shadow_ai_detected")
def shadow_ai_detected(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Detect unauthorized AI API calls in proxy/CASB logs.

    Analyzes Zscaler/Netskope data for api.openai.com, api.anthropic.com traffic.
    """
    reasons: list[str] = []

    # Known AI API domains
    ai_domains = {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.cohere.ai",
        "api.mistral.ai",
        "api.together.xyz",
        "api.replicate.com",
        "api.ai21.com",
        "api-inference.huggingface.co",
    }

    # CASB/Proxy findings
    domain = detail.get("domain") or detail.get("url_host") or detail.get("hostname") or ""
    if domain and domain.lower() in ai_domains:
        approved = detail.get("approved") or detail.get("sanctioned") or detail.get("allowed")
        if approved is False or not approved:
            user = (
                detail.get("user") or detail.get("username") or detail.get("source_ip") or "unknown"
            )
            reasons.append(f"Unauthorized AI API access to {domain} by {user}")
            return False, reasons

    # Shadow AI summary
    unauthorized_ai_apps = detail.get("unauthorized_ai_apps") or detail.get("shadowAiApps", [])
    if isinstance(unauthorized_ai_apps, list) and unauthorized_ai_apps:
        reasons.append(
            f"{len(unauthorized_ai_apps)} unauthorized AI applications detected: "
            f"{', '.join(str(a) for a in unauthorized_ai_apps[:5])}"
        )
        return False, reasons

    # AI traffic volume
    ai_traffic = detail.get("ai_api_requests") or detail.get("aiTrafficCount")
    if ai_traffic is not None and int(ai_traffic) > 0:
        if not detail.get("approved", True):
            reasons.append(f"{ai_traffic} unauthorized AI API requests detected")
            return False, reasons

    return True, []


# ---------------------------------------------------------------------------
# Additional assertions — Expanded coverage
# ---------------------------------------------------------------------------


@engine.assertion("encryption_in_transit")
def encryption_in_transit(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify data in transit is encrypted (HTTPS, TLS, SSH).

    Checks load balancers, API gateways, database connections.
    """
    reasons: list[str] = []

    # HTTP redirect to HTTPS
    https_only = (
        detail.get("https_only") or detail.get("httpsOnly") or detail.get("redirect_to_https")
    )
    if https_only is False:
        resource = detail.get("name") or detail.get("endpoint") or "unknown"
        reasons.append(f"Resource {resource} does not enforce HTTPS")
        return False, reasons

    # Database SSL required
    ssl_enforcement = (
        detail.get("sslEnforcement") or detail.get("ssl_enforcement") or detail.get("require_ssl")
    )
    if ssl_enforcement is not None:
        if str(ssl_enforcement).lower() in ("disabled", "false", "off") or ssl_enforcement is False:
            db = detail.get("name") or detail.get("serverName") or "unknown"
            reasons.append(f"Database {db} does not require SSL/TLS connections")
            return False, reasons
        return True, []

    # Redis/cache encryption in transit
    transit_encryption = detail.get("TransitEncryptionEnabled") or detail.get("transit_encryption")
    if transit_encryption is False:
        cache = detail.get("CacheClusterId") or detail.get("name") or "unknown"
        reasons.append(f"Cache {cache} does not have transit encryption enabled")
        return False, reasons
    if transit_encryption is True:
        return True, []

    if https_only is True:
        return True, []

    return True, []


@engine.assertion("kms_key_rotation_enabled")
def kms_key_rotation_enabled(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify KMS key rotation is enabled.

    Checks AWS KMS, Azure Key Vault, GCP Cloud KMS.
    """
    reasons: list[str] = []

    # AWS KMS key rotation
    rotation_enabled = detail.get("KeyRotationEnabled") or detail.get("key_rotation_enabled")
    if rotation_enabled is not None:
        if rotation_enabled is False:
            key_id = detail.get("KeyId") or detail.get("key_id") or "unknown"
            reasons.append(f"KMS key {key_id} does not have automatic rotation enabled")
            return False, reasons
        return True, []

    # Azure Key Vault key
    key_attributes = detail.get("attributes", {})
    if isinstance(key_attributes, dict) and key_attributes.get("enabled") is not None:
        rotation_policy = detail.get("rotationPolicy") or detail.get("rotation_policy")
        if not rotation_policy:
            key_name = detail.get("name") or detail.get("kid") or "unknown"
            reasons.append(f"Key Vault key {key_name} has no rotation policy")
            return False, reasons
        return True, []

    # GCP Cloud KMS
    rotation_period = detail.get("rotationPeriod") or detail.get("rotation_period")
    if rotation_period:
        return True, []
    if detail.get("purpose") and not rotation_period:
        key_name = detail.get("name") or "unknown"
        reasons.append(f"GCP KMS key {key_name} has no rotation period configured")
        return False, reasons

    return True, []


@engine.assertion("secrets_management_enforced")
def secrets_management_enforced(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify secrets are stored in a secrets manager, not hardcoded.

    Checks for hardcoded secrets, vault usage, rotation.
    """
    reasons: list[str] = []

    # Hardcoded secret detected
    hardcoded = (
        detail.get("hardcoded_secret") or detail.get("secretInCode") or detail.get("exposed_secret")
    )
    if hardcoded is True:
        file_path = detail.get("file") or detail.get("path") or detail.get("location") or "unknown"
        reasons.append(f"Hardcoded secret detected in {file_path}")
        return False, reasons

    # Secrets manager usage
    vault_enabled = detail.get("vault_enabled") or detail.get("secretsManagerEnabled")
    if vault_enabled is False:
        env = detail.get("environment") or detail.get("name") or "unknown"
        reasons.append(f"Environment {env} does not use a secrets manager")
        return False, reasons

    # Secret rotation
    last_rotated = detail.get("lastRotatedDate") or detail.get("last_rotated")
    if last_rotated:
        days = _days_since(str(last_rotated))
        if days is not None and days > 90:
            secret_name = detail.get("name") or detail.get("SecretName") or "unknown"
            reasons.append(f"Secret {secret_name} last rotated {days} days ago (>90)")
            return False, reasons

    # Scanner findings
    findings = detail.get("secret_findings") or detail.get("secretScanAlerts", [])
    if isinstance(findings, list) and findings:
        open_findings = [f for f in findings if f.get("state", f.get("status", "")) != "resolved"]
        if open_findings:
            reasons.append(f"{len(open_findings)} unresolved secret scanning alerts")
            return False, reasons

    return True, []


@engine.assertion("database_audit_logging")
def database_audit_logging(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify database audit logging is enabled.

    Checks RDS, Azure SQL, GCP Cloud SQL audit configurations.
    """
    reasons: list[str] = []

    # RDS audit logging
    log_types = detail.get("EnabledCloudwatchLogsExports") or detail.get(
        "enabled_cloudwatch_logs", []
    )
    if isinstance(log_types, list):
        if "audit" not in log_types and "postgresql" not in log_types:
            db = detail.get("DBInstanceIdentifier") or detail.get("name") or "unknown"
            if log_types or detail.get("DBInstanceIdentifier"):
                reasons.append(f"Database {db} does not have audit logging exported to CloudWatch")
                return False, reasons
        else:
            return True, []

    # Azure SQL auditing
    audit_state = detail.get("state") or detail.get("auditingState")
    if audit_state is not None and detail.get("type", "").endswith("auditingSettings"):
        if str(audit_state).lower() == "disabled":
            db = detail.get("name") or "unknown"
            reasons.append(f"Azure SQL audit logging is disabled for {db}")
            return False, reasons
        return True, []

    # GCP Cloud SQL
    db_flags = detail.get("databaseFlags") or detail.get("database_flags", [])
    if isinstance(db_flags, list):
        audit_flags = [
            f
            for f in db_flags
            if "audit" in str(f.get("name", "")).lower() or "log" in str(f.get("name", "")).lower()
        ]
        if db_flags and not audit_flags:
            db = detail.get("name") or "unknown"
            reasons.append(f"Cloud SQL instance {db} has no audit logging flags configured")
            return False, reasons

    return True, []


@engine.assertion("mfa_for_privileged_actions")
def mfa_for_privileged_actions(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify MFA is required for privileged/destructive operations.

    Checks step-up auth policies, MFA delete, console access.
    """
    reasons: list[str] = []

    # S3 MFA Delete
    mfa_delete = detail.get("MFADelete") or detail.get("mfa_delete")
    if mfa_delete is not None:
        if str(mfa_delete).lower() in ("disabled", "false") or mfa_delete is False:
            bucket = detail.get("Name") or detail.get("bucket_name") or "unknown"
            reasons.append(f"S3 bucket {bucket} does not require MFA for delete operations")
            return False, reasons
        return True, []

    # Step-up authentication for admin actions
    step_up = detail.get("step_up_auth") or detail.get("stepUpAuthentication")
    if step_up is False:
        policy = detail.get("name") or detail.get("policy_name") or "unknown"
        reasons.append(f"Step-up authentication not required for privileged actions in {policy}")
        return False, reasons
    if step_up is True:
        return True, []

    # AWS root account MFA
    root_mfa = detail.get("root_mfa_enabled") or detail.get("AccountMFAEnabled")
    if root_mfa is not None:
        if root_mfa is False or root_mfa == 0:
            reasons.append("Root/admin account does not have MFA enabled")
            return False, reasons
        return True, []

    return True, []


@engine.assertion("data_classification_applied")
def data_classification_applied(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify data assets have classification labels applied.

    Checks Purview, Macie, data catalog classifications.
    """
    reasons: list[str] = []

    # Classification status
    classified = (
        detail.get("classified") or detail.get("classificationApplied") or detail.get("has_label")
    )
    if classified is False:
        resource = (
            detail.get("name")
            or detail.get("resource_name")
            or detail.get("bucketName")
            or "unknown"
        )
        reasons.append(f"Data asset {resource} has no classification label")
        return False, reasons

    # Sensitive data without classification
    sensitivity = detail.get("sensitivity_level") or detail.get("sensitiveInfoTypes", [])
    classification = detail.get("classification") or detail.get("label")
    if sensitivity and not classification:
        resource = detail.get("name") or detail.get("resource_name") or "unknown"
        reasons.append(f"Data asset {resource} contains sensitive data but has no classification")
        return False, reasons

    # Macie findings
    finding_type = detail.get("type") or detail.get("findingType") or ""
    if "SensitiveData" in str(finding_type):
        bucket = (
            detail.get("resourcesAffected", {}).get("s3Bucket", {}).get("name", "unknown")
            if isinstance(detail.get("resourcesAffected"), dict)
            else "unknown"
        )
        if not detail.get("classification"):
            reasons.append(f"Sensitive data found in {bucket} without classification")
            return False, reasons

    return True, []


@engine.assertion("logging_coverage_complete")
def logging_coverage_complete(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify all critical systems forward logs to SIEM.

    Checks log source coverage against asset inventory.
    """
    reasons: list[str] = []

    # Coverage percentage
    coverage_pct = detail.get("coverage_pct") or detail.get("logCoveragePercent")
    if coverage_pct is not None:
        if float(coverage_pct) < 90:
            reasons.append(f"Logging coverage is {coverage_pct}% (<90% target)")
            return False, reasons
        return True, []

    # Missing log sources
    missing_sources = detail.get("missing_sources") or detail.get("uncoveredAssets", [])
    if isinstance(missing_sources, list) and missing_sources:
        reasons.append(f"{len(missing_sources)} critical systems not forwarding logs to SIEM")
        return False, reasons

    # Individual system log forwarding
    log_forwarding = detail.get("log_forwarding") or detail.get("logForwarding")
    if log_forwarding is False:
        system = detail.get("name") or detail.get("hostname") or "unknown"
        reasons.append(f"System {system} is not forwarding logs to SIEM")
        return False, reasons
    if log_forwarding is True:
        return True, []

    return True, []


@engine.assertion("rbac_configured")
def rbac_configured(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify role-based access control is configured (not direct user permissions).

    Checks for direct IAM user policies vs role-based assignments.
    """
    reasons: list[str] = []

    # Direct user policies (should use roles/groups instead)
    user_policies = (
        detail.get("UserPolicyList")
        or detail.get("attached_user_policies")
        or detail.get("inline_policies", [])
    )
    if isinstance(user_policies, list) and user_policies:
        user = detail.get("UserName") or detail.get("user") or "unknown"
        reasons.append(
            f"User {user} has {len(user_policies)} direct policy attachment(s) — use roles/groups instead"
        )
        return False, reasons

    # RBAC enabled check
    rbac_enabled = detail.get("rbac_enabled") or detail.get("roleBasedAccess")
    if rbac_enabled is False:
        system = detail.get("name") or detail.get("system_name") or "unknown"
        reasons.append(f"System {system} does not use role-based access control")
        return False, reasons
    if rbac_enabled is True:
        return True, []

    # Kubernetes RBAC
    if detail.get("kind") == "ClusterRoleBinding" or detail.get("kind") == "RoleBinding":
        subjects = detail.get("subjects", [])
        for subj in subjects if isinstance(subjects, list) else []:
            if subj.get("kind") == "User":
                reasons.append(f"Direct user binding in K8s RBAC: {subj.get('name', '?')}")
        if reasons:
            return False, reasons
        return True, []

    return True, []


@engine.assertion("privileged_session_recorded")
def privileged_session_recorded(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify privileged sessions are recorded for audit.

    Checks CyberArk PSM, AWS SSM Session Manager, BeyondTrust.
    """
    reasons: list[str] = []

    # Session recording enabled
    recording = (
        detail.get("session_recording")
        or detail.get("sessionRecording")
        or detail.get("recordSession")
    )
    if recording is not None:
        if recording is False or str(recording).lower() in ("disabled", "off"):
            platform = detail.get("platform") or detail.get("name") or "unknown"
            reasons.append(f"Privileged session recording is disabled for {platform}")
            return False, reasons
        return True, []

    # SSM session logging
    ssm_logging = detail.get("cloudWatchLogGroupName") or detail.get("s3BucketName")
    if detail.get("schemaVersion") and not ssm_logging:
        reasons.append("SSM Session Manager does not log sessions to CloudWatch or S3")
        return False, reasons
    if ssm_logging:
        return True, []

    return True, []


@engine.assertion("multi_region_resilience")
def multi_region_resilience(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify critical systems are deployed across multiple regions/AZs.

    Checks multi-AZ, cross-region replication, global load balancing.
    """
    reasons: list[str] = []

    # Multi-AZ deployment
    multi_az = detail.get("MultiAZ") or detail.get("multi_az")
    if multi_az is False:
        resource = detail.get("DBInstanceIdentifier") or detail.get("name") or "unknown"
        reasons.append(f"Resource {resource} is not deployed in Multi-AZ configuration")
        return False, reasons
    if multi_az is True:
        return True, []

    # Cross-region replication
    cross_region = detail.get("cross_region_replication") or detail.get("ReplicationEnabled")
    if cross_region is False and detail.get("criticality", "").lower() in ("critical", "high"):
        resource = detail.get("name") or "unknown"
        reasons.append(f"Critical resource {resource} has no cross-region replication")
        return False, reasons

    # Availability zones count
    azs = detail.get("availability_zones") or detail.get("AvailabilityZones", [])
    if isinstance(azs, list) and len(azs) == 1:
        resource = detail.get("name") or "unknown"
        reasons.append(f"Resource {resource} is in only 1 availability zone")
        return False, reasons
    if isinstance(azs, list) and len(azs) > 1:
        return True, []

    return True, []


@engine.assertion("account_lockout_configured")
def account_lockout_configured(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify account lockout policies are configured.

    Checks lockout thresholds, duration, and counter reset.
    """
    reasons: list[str] = []

    # Lockout threshold
    threshold = (
        detail.get("lockout_threshold")
        or detail.get("maxAttempts")
        or detail.get("lockoutThreshold")
    )
    if threshold is not None:
        if int(threshold) == 0:
            reasons.append("Account lockout threshold is 0 — no lockout enforcement")
            return False, reasons
        if int(threshold) > 10:
            reasons.append(f"Account lockout threshold is {threshold} (recommended: <=5)")
            return False, reasons
        return True, []

    # Okta lockout policy
    lockout = detail.get("lockout") or detail.get("lockoutPolicy")
    if isinstance(lockout, dict):
        max_attempts = lockout.get("maxAttempts", lockout.get("max_attempts", 0))
        if max_attempts == 0:
            reasons.append("Okta lockout policy allows unlimited failed attempts")
            return False, reasons
        return True, []

    # Entra ID smart lockout
    smart_lockout = detail.get("smartLockout") or detail.get("smart_lockout")
    if isinstance(smart_lockout, dict):
        if not smart_lockout.get("enabled", True):
            reasons.append("Entra ID smart lockout is disabled")
            return False, reasons
        return True, []

    return True, []


@engine.assertion("security_awareness_program")
def security_awareness_program(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify security awareness program is active and current.

    Checks program status, content updates, participation metrics.
    """
    reasons: list[str] = []

    # Program active
    program_active = detail.get("program_active") or detail.get("isActive")
    if program_active is False:
        reasons.append("Security awareness program is not active")
        return False, reasons

    # Content last updated
    content_updated = detail.get("content_last_updated") or detail.get("lastContentUpdate")
    if content_updated:
        days = _days_since(str(content_updated))
        if days is not None and days > 365:
            reasons.append(f"Security awareness content last updated {days} days ago (>365)")
            return False, reasons

    # Participation rate
    participation = detail.get("participation_rate") or detail.get("enrollmentRate")
    if participation is not None:
        if float(participation) < 90:
            reasons.append(f"Security awareness program participation at {participation}% (<90%)")
            return False, reasons

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("secure_sdlc_implemented")
def secure_sdlc_implemented(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify secure software development lifecycle practices.

    Checks SAST/DAST integration, code review requirements, security gates.
    """
    reasons: list[str] = []

    # SAST enabled
    sast_enabled = detail.get("sast_enabled") or detail.get("staticAnalysis")
    if sast_enabled is False:
        repo = detail.get("repository") or detail.get("name") or "unknown"
        reasons.append(f"SAST not enabled for repository {repo}")

    # Code review required
    code_review = (
        detail.get("code_review_required")
        or detail.get("requireReview")
        or detail.get("branch_protection")
    )
    if isinstance(code_review, dict):
        if not code_review.get("required_pull_request_reviews"):
            repo = detail.get("repository") or detail.get("name") or "unknown"
            reasons.append(f"Pull request reviews not required for {repo}")
    elif code_review is False:
        repo = detail.get("repository") or detail.get("name") or "unknown"
        reasons.append(f"Code review not required for {repo}")

    # Branch protection
    branch_protection = detail.get("branch_protection") or detail.get("protectedBranch")
    if isinstance(branch_protection, dict):
        if not branch_protection.get("enabled", True):
            repo = detail.get("repository") or detail.get("name") or "unknown"
            reasons.append(f"Branch protection not enabled for {repo}")

    # DAST enabled
    dast_enabled = detail.get("dast_enabled") or detail.get("dynamicAnalysis")
    if dast_enabled is False:
        repo = detail.get("repository") or detail.get("name") or "unknown"
        reasons.append(f"DAST not enabled for repository {repo}")

    if reasons:
        return False, reasons
    return True, []


@engine.assertion("network_intrusion_detection")
def network_intrusion_detection(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify network IDS/IPS is deployed and active.

    Checks Suricata, Snort, AWS Network Firewall, Palo Alto.
    """
    reasons: list[str] = []

    # IDS/IPS status
    ids_status = (
        detail.get("ids_enabled") or detail.get("ipsEnabled") or detail.get("intrusion_detection")
    )
    if ids_status is not None:
        if ids_status is False or str(ids_status).lower() in ("disabled", "off"):
            network = detail.get("name") or detail.get("network_name") or "unknown"
            reasons.append(f"Network IDS/IPS is disabled for {network}")
            return False, reasons
        return True, []

    # AWS Network Firewall
    firewall_policy = detail.get("FirewallPolicy") or detail.get("firewall_policy")
    if isinstance(firewall_policy, dict):
        stateful_rules = firewall_policy.get("StatefulRuleGroupReferences", [])
        if not stateful_rules:
            reasons.append("AWS Network Firewall has no stateful inspection rules")
            return False, reasons
        return True, []

    # Alert rules active
    alert_rules = detail.get("alert_rules") or detail.get("signatures")
    if isinstance(alert_rules, list):
        if len(alert_rules) == 0:
            reasons.append("No IDS/IPS detection signatures active")
            return False, reasons
        return True, []

    return True, []


@engine.assertion("asset_inventory_complete")
def asset_inventory_complete(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify IT asset inventory is maintained and current.

    Checks CMDB, cloud asset inventory, discovery scan coverage.
    """
    reasons: list[str] = []

    # Inventory coverage
    coverage = detail.get("inventory_coverage") or detail.get("assetCoverage")
    if coverage is not None:
        if float(coverage) < 95:
            reasons.append(f"Asset inventory coverage is {coverage}% (<95%)")
            return False, reasons
        return True, []

    # Last discovery scan
    last_scan = detail.get("last_discovery_scan") or detail.get("lastDiscovery")
    if last_scan:
        days = _days_since(str(last_scan))
        if days is not None and days > 30:
            reasons.append(f"Asset discovery scan last run {days} days ago (>30)")
            return False, reasons
        if days is not None:
            return True, []

    # Unmanaged assets
    unmanaged = detail.get("unmanaged_assets") or detail.get("unknownDevices")
    if isinstance(unmanaged, (int, float)) and unmanaged > 0:
        reasons.append(f"{int(unmanaged)} unmanaged/unknown assets detected on network")
        return False, reasons
    if isinstance(unmanaged, list) and unmanaged:
        reasons.append(f"{len(unmanaged)} unmanaged/unknown assets detected on network")
        return False, reasons

    # CMDB status
    cmdb_status = detail.get("cmdb_status") or detail.get("inventoryStatus")
    if cmdb_status and str(cmdb_status).lower() in ("stale", "incomplete", "outdated"):
        reasons.append(f"Asset inventory status: {cmdb_status}")
        return False, reasons

    return True, []


@engine.assertion("mobile_device_management")
def mobile_device_management(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """Verify mobile devices are enrolled in MDM and meet security policies.

    Checks Intune, Jamf, Workspace ONE enrollment and compliance.
    """
    reasons: list[str] = []

    # Enrollment status
    enrolled = detail.get("enrolled") or detail.get("isManaged") or detail.get("managementState")
    if enrolled is not None:
        if enrolled is False or str(enrolled).lower() in ("unmanaged", "not_enrolled"):
            device = (
                detail.get("deviceName")
                or detail.get("name")
                or detail.get("serialNumber")
                or "unknown"
            )
            reasons.append(f"Device {device} is not enrolled in MDM")
            return False, reasons

    # OS version compliance
    os_compliant = detail.get("os_compliant") or detail.get("osVersionCompliant")
    if os_compliant is False:
        device = detail.get("deviceName") or detail.get("name") or "unknown"
        os_version = detail.get("osVersion") or detail.get("os_version") or "unknown"
        reasons.append(f"Device {device} OS version {os_version} is not compliant")
        return False, reasons

    # Jailbreak/root detection
    jailbroken = (
        detail.get("jailbroken") or detail.get("isRooted") or detail.get("jailBreakDetected")
    )
    if jailbroken is True:
        device = detail.get("deviceName") or detail.get("name") or "unknown"
        reasons.append(f"Device {device} is jailbroken/rooted")
        return False, reasons

    # Passcode set
    passcode = (
        detail.get("passcode_set")
        or detail.get("isDeviceLocked")
        or detail.get("passcodeCompliant")
    )
    if passcode is False:
        device = detail.get("deviceName") or detail.get("name") or "unknown"
        reasons.append(f"Device {device} does not have a passcode configured")
        return False, reasons

    if reasons:
        return False, reasons

    if enrolled is True or str(enrolled or "").lower() in ("enrolled", "managed"):
        return True, []

    return True, []


# ============================================================================
# BINDINGS — New assertions to frameworks
# ============================================================================


# ---------------------------------------------------------------------------
# NIST 800-53 bindings for new assertions
# ---------------------------------------------------------------------------

_NIST_NEW_BINDINGS: list[tuple[str, str]] = [
    # SC — System and Communications Protection (includes expanded assertions)
    ("SC-8", "encryption_in_transit"),
    ("SC-12", "kms_key_rotation_enabled"),
    ("SC-28", "kms_key_rotation_enabled"),
    ("SC-28", "secrets_management_enforced"),
    ("SC-7", "network_intrusion_detection"),
    ("SC-8", "tls_version_current"),
    ("SC-13", "tls_version_current"),
    ("SC-23", "tls_version_current"),
    ("SC-7", "network_segmentation_enforced"),
    ("SC-7", "waf_enabled"),
    ("SC-7", "egress_filtering_active"),
    ("SC-20", "dns_security_enabled"),
    ("SC-21", "dns_security_enabled"),
    ("SC-8", "vpn_tunnel_active"),
    ("SC-12", "vpn_tunnel_active"),
    ("SC-12", "certificate_validity"),
    # AC — Access Control
    ("AC-6", "least_privilege_enforced"),
    ("AC-11", "session_timeout_configured"),
    ("AC-12", "session_timeout_configured"),
    ("AC-2", "account_provisioning_automated"),
    ("AC-2", "inactive_accounts_disabled"),
    ("AC-5", "separation_of_duties"),
    ("AC-17", "remote_access_authorized"),
    ("AC-3", "conditional_access_enforced"),
    ("AC-2", "api_key_rotation"),
    ("AC-18", "wireless_security_compliant"),
    ("AC-19", "mobile_device_management"),
    # AU — Audit and Accountability
    ("AU-11", "audit_log_retention_compliant"),
    ("AU-9", "audit_log_tamper_protection"),
    ("AU-6", "centralized_logging_active"),
    ("AU-2", "failed_login_monitoring"),
    ("AU-6", "failed_login_monitoring"),
    ("AU-3", "admin_action_logging"),
    ("AU-12", "admin_action_logging"),
    ("AU-12", "network_flow_logging"),
    ("AU-8", "time_synchronization"),
    ("AU-12", "database_audit_logging"),
    ("AU-3", "logging_coverage_complete"),
    # IA — Identification and Authentication
    ("IA-2", "mfa_for_privileged_actions"),
    ("IA-2", "strong_authentication_required"),
    ("IA-4", "service_account_managed"),
    ("IA-5", "service_account_managed"),
    ("IA-5", "certificate_validity"),
    ("IA-5", "api_key_rotation"),
    ("IA-5", "default_credentials_removed"),
    ("IA-2", "identity_federation_configured"),
    ("IA-8", "identity_federation_configured"),
    # IR — Incident Response
    ("IR-3", "incident_response_tested"),
    ("IR-4", "threat_detection_alerts_configured"),
    ("IR-6", "threat_detection_alerts_configured"),
    ("IR-4", "malware_detection_active"),
    ("IR-5", "security_incident_tracked"),
    ("IR-6", "security_incident_tracked"),
    # SI — System and Information Integrity
    ("SI-3", "antivirus_definitions_current"),
    ("SI-3", "malware_detection_active"),
    ("SI-7", "file_integrity_monitoring"),
    ("SI-2", "patch_management_current"),
    ("SI-4", "software_whitelist_enforced"),
    ("SI-4", "waf_enabled"),
    ("SI-4", "network_flow_logging"),
    ("SI-8", "spam_protection_active"),
    ("SI-10", "input_validation_enforced"),
    # AT — Awareness and Training
    ("AT-2", "security_awareness_program"),
    ("AT-3", "security_awareness_program"),
    # PM — Program Management
    ("PM-5", "asset_inventory_complete"),
    # SA — System and Services Acquisition
    ("SA-11", "secure_sdlc_implemented"),
    ("SA-15", "secure_sdlc_implemented"),
    # CM — Configuration Management
    ("CM-2", "baseline_configuration_documented"),
    ("CM-3", "configuration_change_tracked"),
    ("CM-7", "unauthorized_software_blocked"),
    ("CM-11", "unauthorized_software_blocked"),
    ("CM-3", "container_image_signed"),
    ("CM-14", "container_image_signed"),
    ("CM-3", "infrastructure_as_code_validated"),
    ("CM-7", "software_whitelist_enforced"),
    # CP — Contingency Planning
    ("CP-9", "backup_encryption_enabled"),
    ("CP-4", "disaster_recovery_tested"),
    ("CP-6", "backup_offsite_stored"),
    ("CP-10", "recovery_time_achievable"),
    # RA — Risk Assessment
    ("RA-5", "vulnerability_remediation_sla"),
    ("RA-7", "vulnerability_remediation_sla"),
    ("RA-3", "risk_assessment_current"),
    ("CA-8", "penetration_test_current"),
    # AC — Access Control (expanded)
    ("AC-3", "rbac_configured"),
    ("AC-2", "account_lockout_configured"),
    ("AC-6", "privileged_session_recorded"),
    # SC — Expanded
    ("SC-36", "multi_region_resilience"),
    ("CP-7", "multi_region_resilience"),
    # RA — Expanded
    ("RA-2", "data_classification_applied"),
    # PS — Personnel Security
    ("PS-4", "termination_access_revoked"),
    ("PS-5", "role_change_access_reviewed"),
    ("PS-3", "security_clearance_verified"),
    # PE — Physical and Environmental
    ("PE-2", "physical_access_controlled"),
    ("PE-3", "physical_access_controlled"),
    ("PE-8", "visitor_access_logged"),
    # SR — Supply Chain Risk Management
    ("SR-6", "vendor_risk_assessed"),
    ("SR-3", "third_party_sla_monitored"),
    ("SA-9", "vendor_risk_assessed"),
    ("SA-10", "infrastructure_as_code_validated"),
    # PT — Privacy (PII controls in NIST)
    ("PT-3", "data_minimization_verified"),
    ("PT-4", "consent_mechanism_active"),
]

for _ctrl, _assertion in _NIST_NEW_BINDINGS:
    engine.bind_control("nist_800_53", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# FedRAMP bindings (same as NIST 800-53 for scoping)
# ---------------------------------------------------------------------------

for _ctrl, _assertion in _NIST_NEW_BINDINGS:
    engine.bind_control("fedramp", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# SOC 2 bindings for new assertions
# ---------------------------------------------------------------------------

_SOC2_NEW_BINDINGS: list[tuple[str, str]] = [
    # CC1 — Control Environment
    ("CC1.1", "security_clearance_verified"),
    ("CC1.4", "incident_response_tested"),
    # CC2 — Communication and Information
    ("CC2.1", "data_minimization_verified"),
    # CC3 — Risk Assessment
    ("CC3.1", "risk_assessment_current"),
    ("CC3.2", "vulnerability_remediation_sla"),
    ("CC3.4", "penetration_test_current"),
    # CC5 — Control Activities
    ("CC5.1", "baseline_configuration_documented"),
    ("CC5.2", "configuration_change_tracked"),
    # CC6 — Logical and Physical Access
    ("CC6.1", "least_privilege_enforced"),
    ("CC6.1", "session_timeout_configured"),
    ("CC6.1", "conditional_access_enforced"),
    ("CC6.1", "identity_federation_configured"),
    ("CC6.2", "account_provisioning_automated"),
    ("CC6.2", "inactive_accounts_disabled"),
    ("CC6.2", "termination_access_revoked"),
    ("CC6.3", "separation_of_duties"),
    ("CC6.4", "physical_access_controlled"),
    ("CC6.5", "visitor_access_logged"),
    ("CC6.6", "tls_version_current"),
    ("CC6.6", "network_segmentation_enforced"),
    ("CC6.6", "waf_enabled"),
    ("CC6.7", "egress_filtering_active"),
    ("CC6.8", "malware_detection_active"),
    ("CC6.8", "antivirus_definitions_current"),
    # CC7 — System Operations
    ("CC7.1", "threat_detection_alerts_configured"),
    ("CC7.1", "file_integrity_monitoring"),
    ("CC7.2", "network_flow_logging"),
    ("CC7.2", "centralized_logging_active"),
    ("CC7.2", "admin_action_logging"),
    ("CC7.3", "patch_management_current"),
    ("CC7.4", "security_incident_tracked"),
    # CC8 — Change Management
    ("CC8.1", "container_image_signed"),
    ("CC8.1", "infrastructure_as_code_validated"),
    # CC9 — Risk Mitigation
    ("CC9.1", "vendor_risk_assessed"),
    ("CC9.2", "third_party_sla_monitored"),
    # A1 — Availability
    ("A1.1", "disaster_recovery_tested"),
    ("A1.2", "backup_encryption_enabled"),
    ("A1.2", "backup_offsite_stored"),
    ("A1.3", "recovery_time_achievable"),
    # C1 — Confidentiality
    ("C1.1", "tls_version_current"),
    ("C1.2", "data_minimization_verified"),
    # PI1 — Processing Integrity
    ("PI1.1", "input_validation_enforced"),
    # P1 — Privacy
    ("P1.1", "consent_mechanism_active"),
    # Additional new assertion bindings
    ("CC6.1", "rbac_configured"),
    ("CC6.1", "account_lockout_configured"),
    ("CC6.3", "privileged_session_recorded"),
    ("CC6.6", "encryption_in_transit"),
    ("CC6.7", "secrets_management_enforced"),
    ("CC7.1", "network_intrusion_detection"),
    ("CC7.2", "database_audit_logging"),
    ("CC7.2", "logging_coverage_complete"),
    ("CC8.1", "secure_sdlc_implemented"),
    ("CC1.4", "security_awareness_program"),
    ("C1.1", "kms_key_rotation_enabled"),
    ("A1.1", "multi_region_resilience"),
    ("CC3.2", "data_classification_applied"),
    ("CC3.1", "asset_inventory_complete"),
    ("CC6.8", "mfa_for_privileged_actions"),
]

for _ctrl, _assertion in _SOC2_NEW_BINDINGS:
    engine.bind_control("soc2", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# ISO 27001:2022 bindings for new assertions
# ---------------------------------------------------------------------------

_ISO27001_NEW_BINDINGS: list[tuple[str, str]] = [
    ("A.5.2", "least_privilege_enforced"),  # Information security roles
    ("A.5.3", "separation_of_duties"),  # Segregation of duties
    ("A.5.9", "baseline_configuration_documented"),  # Inventory of information
    ("A.5.14", "tls_version_current"),  # Information transfer
    ("A.5.15", "session_timeout_configured"),  # Access control
    ("A.5.15", "conditional_access_enforced"),  # Access control
    ("A.5.16", "account_provisioning_automated"),  # Identity management
    ("A.5.16", "inactive_accounts_disabled"),  # Identity management
    ("A.5.17", "strong_authentication_required"),  # Authentication
    ("A.5.18", "least_privilege_enforced"),  # Access rights
    ("A.5.19", "vendor_risk_assessed"),  # Supplier relationships
    ("A.5.20", "third_party_sla_monitored"),  # ICT supply chain
    ("A.5.22", "vendor_risk_assessed"),  # Supplier monitoring
    ("A.5.24", "incident_response_tested"),  # Incident management planning
    ("A.5.25", "security_incident_tracked"),  # Assessment of security events
    ("A.5.26", "security_incident_tracked"),  # Response to incidents
    ("A.5.30", "disaster_recovery_tested"),  # ICT readiness for BC
    ("A.5.33", "data_minimization_verified"),  # Protection of records
    ("A.5.34", "consent_mechanism_active"),  # Privacy and PII
    ("A.5.36", "baseline_configuration_documented"),  # Compliance with policies
    ("A.6.1", "security_clearance_verified"),  # Screening
    ("A.6.4", "termination_access_revoked"),  # Disciplinary process
    ("A.6.5", "termination_access_revoked"),  # After termination
    ("A.7.1", "physical_access_controlled"),  # Physical security perimeters
    ("A.7.2", "physical_access_controlled"),  # Physical entry
    ("A.7.4", "visitor_access_logged"),  # Physical security monitoring
    ("A.8.1", "wireless_security_compliant"),  # User endpoint devices
    ("A.8.2", "service_account_managed"),  # Privileged access rights
    ("A.8.3", "least_privilege_enforced"),  # Information access restriction
    ("A.8.5", "identity_federation_configured"),  # Secure authentication
    ("A.8.6", "baseline_configuration_documented"),  # Capacity management
    ("A.8.7", "malware_detection_active"),  # Protection against malware
    ("A.8.7", "antivirus_definitions_current"),  # Protection against malware
    ("A.8.8", "patch_management_current"),  # Technical vuln management
    ("A.8.9", "configuration_change_tracked"),  # Configuration management
    ("A.8.10", "data_minimization_verified"),  # Information deletion
    ("A.8.12", "egress_filtering_active"),  # Data leakage prevention
    ("A.8.13", "backup_encryption_enabled"),  # Information backup
    ("A.8.14", "centralized_logging_active"),  # Redundancy of info processing
    ("A.8.15", "audit_log_retention_compliant"),  # Logging
    ("A.8.15", "admin_action_logging"),  # Logging
    ("A.8.16", "network_flow_logging"),  # Monitoring activities
    ("A.8.20", "network_segmentation_enforced"),  # Network security
    ("A.8.21", "waf_enabled"),  # Security of network services
    ("A.8.22", "network_segmentation_enforced"),  # Segregation of networks
    ("A.8.23", "egress_filtering_active"),  # Web filtering
    ("A.8.24", "certificate_validity"),  # Use of cryptography
    ("A.8.25", "infrastructure_as_code_validated"),  # Secure development lifecycle
    ("A.8.26", "input_validation_enforced"),  # Application security requirements
    ("A.8.28", "container_image_signed"),  # Secure coding
    ("A.8.31", "separation_of_duties"),  # Separation of environments
    ("A.8.32", "configuration_change_tracked"),  # Change management
    # Additional new assertions
    ("A.5.9", "asset_inventory_complete"),  # Inventory of information
    ("A.5.10", "data_classification_applied"),  # Information classification
    ("A.5.12", "data_classification_applied"),  # Classification of information
    ("A.5.14", "encryption_in_transit"),  # Information transfer
    ("A.8.2", "privileged_session_recorded"),  # Privileged access rights
    ("A.8.5", "account_lockout_configured"),  # Secure authentication
    ("A.8.5", "rbac_configured"),  # Secure authentication
    ("A.8.7", "antivirus_definitions_current"),  # Protection against malware
    ("A.8.9", "kms_key_rotation_enabled"),  # Configuration management
    ("A.8.17", "database_audit_logging"),  # Clock synchronization
    ("A.8.21", "network_intrusion_detection"),  # Security of network services
    ("A.8.24", "kms_key_rotation_enabled"),  # Use of cryptography
    ("A.8.25", "secure_sdlc_implemented"),  # Secure development lifecycle
    ("A.8.26", "secure_sdlc_implemented"),  # Application security requirements
    ("A.8.27", "secrets_management_enforced"),  # Secure system architecture
    ("A.8.30", "multi_region_resilience"),  # ICT readiness for BC
    ("A.6.3", "security_awareness_program"),  # Awareness
    ("A.8.15", "logging_coverage_complete"),  # Logging
]

for _ctrl, _assertion in _ISO27001_NEW_BINDINGS:
    engine.bind_control("iso_27001", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# HIPAA bindings for new assertions
# ---------------------------------------------------------------------------

_HIPAA_NEW_BINDINGS: list[tuple[str, str]] = [
    # 164.308 — Administrative Safeguards
    ("164.308(a)(1)(i)", "risk_assessment_current"),
    ("164.308(a)(1)(i)", "vulnerability_remediation_sla"),
    ("164.308(a)(3)(i)", "termination_access_revoked"),
    ("164.308(a)(3)(ii)(C)", "termination_access_revoked"),
    ("164.308(a)(4)(i)", "least_privilege_enforced"),
    ("164.308(a)(4)(i)", "inactive_accounts_disabled"),
    ("164.308(a)(5)(i)", "antivirus_definitions_current"),
    ("164.308(a)(6)(i)", "incident_response_tested"),
    ("164.308(a)(6)(i)", "security_incident_tracked"),
    ("164.308(a)(7)(i)", "disaster_recovery_tested"),
    ("164.308(a)(7)(ii)(D)", "recovery_time_achievable"),
    # 164.310 — Physical Safeguards
    ("164.310(a)(1)", "physical_access_controlled"),
    ("164.310(a)(2)(ii)", "visitor_access_logged"),
    ("164.310(d)(1)", "backup_encryption_enabled"),
    # 164.312 — Technical Safeguards
    ("164.312(a)(1)", "session_timeout_configured"),
    ("164.312(a)(1)", "conditional_access_enforced"),
    ("164.312(a)(2)(i)", "identity_federation_configured"),
    ("164.312(b)", "audit_log_retention_compliant"),
    ("164.312(b)", "admin_action_logging"),
    ("164.312(b)", "centralized_logging_active"),
    ("164.312(c)(1)", "file_integrity_monitoring"),
    ("164.312(d)", "strong_authentication_required"),
    ("164.312(e)(1)", "tls_version_current"),
    # 164.314 — Business Associates
    ("164.314(a)(1)", "vendor_risk_assessed"),
    # 164.316 — Policies
    ("164.316(b)(1)", "baseline_configuration_documented"),
]

for _ctrl, _assertion in _HIPAA_NEW_BINDINGS:
    engine.bind_control("hipaa", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# PCI DSS 4.0 bindings for new assertions
# ---------------------------------------------------------------------------

_PCI_NEW_BINDINGS: list[tuple[str, str]] = [
    # R1 — Network Security
    ("R1.2", "network_segmentation_enforced"),
    ("R1.2", "waf_enabled"),
    ("R1.3", "egress_filtering_active"),
    ("R1.4", "network_flow_logging"),
    # R2 — Secure Configurations
    ("R2.1", "default_credentials_removed"),
    ("R2.2", "baseline_configuration_documented"),
    # R3 — Protect Stored Data
    ("R3.5", "api_key_rotation"),
    # R4 — Encryption in Transit
    ("R4.1", "tls_version_current"),
    ("R4.2", "certificate_validity"),
    # R5 — Malware
    ("R5.2", "antivirus_definitions_current"),
    ("R5.3", "malware_detection_active"),
    # R6 — Secure Systems
    ("R6.2", "container_image_signed"),
    ("R6.3", "patch_management_current"),
    ("R6.4", "input_validation_enforced"),
    ("R6.4", "waf_enabled"),
    # R7 — Access
    ("R7.1", "least_privilege_enforced"),
    ("R7.2", "separation_of_duties"),
    # R8 — Authentication
    ("R8.2", "inactive_accounts_disabled"),
    ("R8.3", "strong_authentication_required"),
    ("R8.6", "service_account_managed"),
    # R9 — Physical Access
    ("R9.1", "physical_access_controlled"),
    ("R9.4", "visitor_access_logged"),
    # R10 — Logging
    ("R10.2", "admin_action_logging"),
    ("R10.3", "time_synchronization"),
    ("R10.5", "audit_log_tamper_protection"),
    ("R10.7", "audit_log_retention_compliant"),
    # R11 — Security Testing
    ("R11.3", "penetration_test_current"),
    ("R11.4", "threat_detection_alerts_configured"),
    ("R11.5", "file_integrity_monitoring"),
    ("R11.6", "configuration_change_tracked"),
    # R12 — Policies
    ("R12.3", "risk_assessment_current"),
    ("R12.8", "vendor_risk_assessed"),
    ("R12.9", "third_party_sla_monitored"),
    ("R12.10", "incident_response_tested"),
    ("R12.10", "security_incident_tracked"),
]

for _ctrl, _assertion in _PCI_NEW_BINDINGS:
    engine.bind_control("pci_dss", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# CMMC L2 bindings for new assertions
# ---------------------------------------------------------------------------

_CMMC_NEW_BINDINGS: list[tuple[str, str]] = [
    # AC — Access Control
    ("AC.L2-3.1.1", "inactive_accounts_disabled"),
    ("AC.L2-3.1.2", "least_privilege_enforced"),
    ("AC.L2-3.1.3", "egress_filtering_active"),
    ("AC.L2-3.1.4", "separation_of_duties"),
    ("AC.L2-3.1.5", "session_timeout_configured"),
    ("AC.L2-3.1.12", "remote_access_authorized"),
    ("AC.L2-3.1.13", "remote_access_authorized"),
    ("AC.L2-3.1.14", "vpn_tunnel_active"),
    ("AC.L2-3.1.16", "wireless_security_compliant"),
    ("AC.L2-3.1.17", "wireless_security_compliant"),
    ("AC.L2-3.1.18", "remote_access_authorized"),
    # AU — Audit
    ("AU.L2-3.3.1", "admin_action_logging"),
    ("AU.L2-3.3.2", "audit_log_tamper_protection"),
    ("AU.L2-3.3.5", "centralized_logging_active"),
    ("AU.L2-3.3.7", "time_synchronization"),
    ("AU.L2-3.3.8", "audit_log_retention_compliant"),
    # CM — Configuration Management
    ("CM.L2-3.4.1", "baseline_configuration_documented"),
    ("CM.L2-3.4.2", "configuration_change_tracked"),
    ("CM.L2-3.4.5", "default_credentials_removed"),
    ("CM.L2-3.4.8", "unauthorized_software_blocked"),
    # IA — Identification and Authentication
    ("IA.L2-3.5.1", "strong_authentication_required"),
    ("IA.L2-3.5.2", "service_account_managed"),
    ("IA.L2-3.5.3", "identity_federation_configured"),
    ("IA.L2-3.5.4", "api_key_rotation"),
    # IR — Incident Response
    ("IR.L2-3.6.1", "incident_response_tested"),
    ("IR.L2-3.6.2", "security_incident_tracked"),
    ("IR.L2-3.6.3", "threat_detection_alerts_configured"),
    # MA — Maintenance
    ("MA.L2-3.7.5", "remote_access_authorized"),
    # MP — Media Protection
    ("MP.L2-3.8.6", "backup_encryption_enabled"),
    # PE — Physical Protection
    ("PE.L2-3.10.1", "physical_access_controlled"),
    ("PE.L2-3.10.3", "visitor_access_logged"),
    ("PE.L2-3.10.5", "physical_access_controlled"),
    # PS — Personnel Security
    ("PS.L2-3.9.1", "security_clearance_verified"),
    ("PS.L2-3.9.2", "termination_access_revoked"),
    # RA — Risk Assessment
    ("RA.L2-3.11.1", "risk_assessment_current"),
    ("RA.L2-3.11.2", "vulnerability_remediation_sla"),
    ("RA.L2-3.11.3", "penetration_test_current"),
    # CA — Security Assessment
    ("CA.L2-3.12.1", "baseline_configuration_documented"),
    ("CA.L2-3.12.4", "infrastructure_as_code_validated"),
    # SC — System and Communications Protection
    ("SC.L2-3.13.1", "network_segmentation_enforced"),
    ("SC.L2-3.13.2", "network_segmentation_enforced"),
    ("SC.L2-3.13.4", "tls_version_current"),
    ("SC.L2-3.13.5", "waf_enabled"),
    ("SC.L2-3.13.7", "dns_security_enabled"),
    ("SC.L2-3.13.8", "tls_version_current"),
    ("SC.L2-3.13.15", "remote_access_authorized"),
    # SI — System and Information Integrity
    ("SI.L2-3.14.1", "patch_management_current"),
    ("SI.L2-3.14.2", "malware_detection_active"),
    ("SI.L2-3.14.2", "antivirus_definitions_current"),
    ("SI.L2-3.14.4", "network_flow_logging"),
    ("SI.L2-3.14.6", "file_integrity_monitoring"),
    ("SI.L2-3.14.7", "spam_protection_active"),
]

for _ctrl, _assertion in _CMMC_NEW_BINDINGS:
    engine.bind_control("cmmc_l2", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# GDPR bindings for new assertions
# ---------------------------------------------------------------------------

_GDPR_NEW_BINDINGS: list[tuple[str, str]] = [
    # Art 5 — Principles
    ("Art5-1c", "data_minimization_verified"),  # Data minimization
    ("Art5-1e", "data_minimization_verified"),  # Storage limitation
    ("Art5-1f", "tls_version_current"),  # Integrity/confidentiality
    ("Art5-1f", "audit_log_tamper_protection"),  # Integrity/confidentiality
    # Art 6-7 — Legal Basis and Consent
    ("Art6-1", "consent_mechanism_active"),
    ("Art7-1", "consent_mechanism_active"),
    # Art 25 — Data Protection by Design
    ("Art25-1", "data_minimization_verified"),
    ("Art25-2", "data_minimization_verified"),
    # Art 28 — Processors
    ("Art28-1", "vendor_risk_assessed"),
    ("Art28-3", "third_party_sla_monitored"),
    # Art 30 — Records of Processing
    ("Art30-1", "ai_model_inventory_current"),
    # Art 32 — Security of Processing
    ("Art32-1", "tls_version_current"),
    ("Art32-1", "least_privilege_enforced"),
    ("Art32-1", "incident_response_tested"),
    ("Art32-1", "backup_encryption_enabled"),
    ("Art32-1", "patch_management_current"),
    # Art 33-34 — Breach Notification
    ("Art33-1", "security_incident_tracked"),
    ("Art33-1", "threat_detection_alerts_configured"),
    # Art 35 — DPIA
    ("Art35-1", "risk_assessment_current"),
]

for _ctrl, _assertion in _GDPR_NEW_BINDINGS:
    engine.bind_control("gdpr", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# NIST CSF 2.0 bindings for new assertions
# ---------------------------------------------------------------------------

_NIST_CSF_NEW_BINDINGS: list[tuple[str, str]] = [
    # Govern
    ("GV.OC-01", "risk_assessment_current"),
    ("GV.RM-01", "risk_assessment_current"),
    ("GV.SC-01", "vendor_risk_assessed"),
    ("GV.SC-02", "third_party_sla_monitored"),
    # Identify
    ("ID.AM-01", "baseline_configuration_documented"),
    ("ID.AM-02", "ai_model_inventory_current"),
    ("ID.RA-01", "vulnerability_remediation_sla"),
    ("ID.RA-05", "penetration_test_current"),
    # Protect
    ("PR.AA-01", "least_privilege_enforced"),
    ("PR.AA-01", "inactive_accounts_disabled"),
    ("PR.AA-03", "strong_authentication_required"),
    ("PR.AA-03", "identity_federation_configured"),
    ("PR.AA-04", "service_account_managed"),
    ("PR.AA-06", "physical_access_controlled"),
    ("PR.AT-01", "incident_response_tested"),
    ("PR.DS-01", "tls_version_current"),
    ("PR.DS-01", "backup_encryption_enabled"),
    ("PR.DS-02", "network_segmentation_enforced"),
    ("PR.DS-02", "egress_filtering_active"),
    ("PR.IR-01", "waf_enabled"),
    ("PR.IR-01", "dns_security_enabled"),
    ("PR.PS-01", "patch_management_current"),
    ("PR.PS-02", "container_image_signed"),
    ("PR.PS-04", "audit_log_retention_compliant"),
    ("PR.PS-04", "admin_action_logging"),
    ("PR.PS-06", "input_validation_enforced"),
    # Detect
    ("DE.CM-01", "malware_detection_active"),
    ("DE.CM-01", "file_integrity_monitoring"),
    ("DE.CM-02", "network_flow_logging"),
    ("DE.CM-06", "centralized_logging_active"),
    ("DE.CM-09", "antivirus_definitions_current"),
    ("DE.AE-02", "threat_detection_alerts_configured"),
    ("DE.AE-03", "failed_login_monitoring"),
    # Respond
    ("RS.MA-01", "security_incident_tracked"),
    ("RS.MA-02", "incident_response_tested"),
    # Recover
    ("RC.RP-01", "disaster_recovery_tested"),
    ("RC.RP-02", "recovery_time_achievable"),
    ("RC.RP-03", "backup_offsite_stored"),
]

for _ctrl, _assertion in _NIST_CSF_NEW_BINDINGS:
    engine.bind_control("nist_csf", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# ISO 42001 bindings for new AI governance assertions
# ---------------------------------------------------------------------------

_ISO42001_AI_BINDINGS: list[tuple[str, str]] = [
    ("A.2.2", "ai_model_inventory_current"),
    ("A.2.4", "ai_model_inventory_current"),
    ("A.5.3", "ai_model_inventory_current"),
    ("A.5.4", "shadow_ai_detected"),
    ("A.6.1.2", "ai_model_inventory_current"),
    ("A.6.2.3", "ai_model_inventory_current"),
    ("A.6.2.5", "data_minimization_verified"),
    ("A.6.2.12", "shadow_ai_detected"),
    ("A.9.3", "shadow_ai_detected"),
    ("A.9.4", "ai_model_inventory_current"),
    ("A.10.2", "vendor_risk_assessed"),
]

for _ctrl, _assertion in _ISO42001_AI_BINDINGS:
    engine.bind_control("iso_42001", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# EU AI Act bindings for new assertions
# ---------------------------------------------------------------------------

_EU_AI_ACT_NEW_BINDINGS: list[tuple[str, str]] = [
    ("ART5.1", "shadow_ai_detected"),
    ("ART9.1", "risk_assessment_current"),
    ("ART9.2", "ai_model_inventory_current"),
    ("ART9.4", "vulnerability_remediation_sla"),
    ("ART10.1", "data_minimization_verified"),
    ("ART10.3", "data_minimization_verified"),
    ("ART13.1", "ai_model_inventory_current"),
    ("ART14.1", "ai_model_inventory_current"),
    ("ART14.4", "shadow_ai_detected"),
    ("ART15.1", "penetration_test_current"),
    ("ART15.3", "malware_detection_active"),
    ("ART15.4", "tls_version_current"),
    ("ART26.1", "ai_model_inventory_current"),
    ("ART26.5", "vendor_risk_assessed"),
    ("ART61.1", "security_incident_tracked"),
]

for _ctrl, _assertion in _EU_AI_ACT_NEW_BINDINGS:
    engine.bind_control("eu_ai_act", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# SEC Cyber bindings for new assertions
# ---------------------------------------------------------------------------

_SEC_CYBER_NEW_BINDINGS: list[tuple[str, str]] = [
    ("ITEM105.1", "incident_response_tested"),
    ("ITEM105.1", "security_incident_tracked"),
    ("ITEM106.B1", "risk_assessment_current"),
    ("ITEM106.B2", "penetration_test_current"),
    ("ITEM106.B3", "vendor_risk_assessed"),
    ("ITEM106.C6", "threat_detection_alerts_configured"),
    ("ITEM106.C6", "centralized_logging_active"),
    ("ANN.1", "disaster_recovery_tested"),
]

for _ctrl, _assertion in _SEC_CYBER_NEW_BINDINGS:
    engine.bind_control("sec_cyber", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# ISO 27701 bindings for new privacy assertions
# ---------------------------------------------------------------------------

_ISO27701_NEW_BINDINGS: list[tuple[str, str]] = [
    ("CL6.5.2.1", "least_privilege_enforced"),
    ("CL6.5.2.1", "session_timeout_configured"),
    ("CL6.5.3.1", "tls_version_current"),
    ("CL6.5.3.1", "certificate_validity"),
    ("CL6.6.2.1", "audit_log_retention_compliant"),
    ("CL6.6.2.1", "admin_action_logging"),
    ("A.7.2.1", "consent_mechanism_active"),
    ("A.7.2.2", "consent_mechanism_active"),
    ("A.7.4.1", "data_minimization_verified"),
    ("A.7.4.4", "data_minimization_verified"),
    ("A.7.4.5", "termination_access_revoked"),
    ("B.8.2.2", "vendor_risk_assessed"),
    ("B.8.4.3", "tls_version_current"),
    ("B.8.5.1", "data_minimization_verified"),
]

for _ctrl, _assertion in _ISO27701_NEW_BINDINGS:
    engine.bind_control("iso_27701", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# UCF bindings for new assertions
# ---------------------------------------------------------------------------

_UCF_NEW_BINDINGS: list[tuple[str, str]] = [
    ("UCF-ACC-1", "least_privilege_enforced"),
    ("UCF-ACC-2", "session_timeout_configured"),
    ("UCF-ACC-3", "inactive_accounts_disabled"),
    ("UCF-ACC-4", "separation_of_duties"),
    ("UCF-ACC-5", "conditional_access_enforced"),
    ("UCF-AUD-1", "audit_log_retention_compliant"),
    ("UCF-AUD-2", "centralized_logging_active"),
    ("UCF-AUD-3", "admin_action_logging"),
    ("UCF-AUD-4", "audit_log_tamper_protection"),
    ("UCF-AUT-1", "strong_authentication_required"),
    ("UCF-AUT-2", "identity_federation_configured"),
    ("UCF-AUT-3", "service_account_managed"),
    ("UCF-AUT-4", "api_key_rotation"),
    ("UCF-CFG-1", "baseline_configuration_documented"),
    ("UCF-CFG-3", "configuration_change_tracked"),
    ("UCF-CFG-4", "unauthorized_software_blocked"),
    ("UCF-BCP-1", "disaster_recovery_tested"),
    ("UCF-BCP-3", "backup_encryption_enabled"),
    ("UCF-BCP-4", "backup_offsite_stored"),
    ("UCF-BCP-5", "recovery_time_achievable"),
    ("UCF-NET-1", "network_segmentation_enforced"),
    ("UCF-NET-2", "waf_enabled"),
    ("UCF-NET-3", "tls_version_current"),
    ("UCF-NET-4", "dns_security_enabled"),
    ("UCF-NET-5", "vpn_tunnel_active"),
    ("UCF-NET-6", "network_flow_logging"),
    ("UCF-NET-7", "egress_filtering_active"),
    ("UCF-NET-8", "wireless_security_compliant"),
    ("UCF-EPP-1", "malware_detection_active"),
    ("UCF-EPP-2", "antivirus_definitions_current"),
    ("UCF-EPP-3", "patch_management_current"),
    ("UCF-EPP-5", "file_integrity_monitoring"),
    ("UCF-DAT-1", "data_minimization_verified"),
    ("UCF-DAT-2", "consent_mechanism_active"),
    ("UCF-DAT-8", "spam_protection_active"),
    ("UCF-DEV-1", "infrastructure_as_code_validated"),
    ("UCF-DEV-4", "container_image_signed"),
    ("UCF-DEV-5", "input_validation_enforced"),
    ("UCF-VEN-1", "vendor_risk_assessed"),
    ("UCF-VEN-2", "third_party_sla_monitored"),
    ("UCF-GOV-1", "risk_assessment_current"),
    ("UCF-GOV-2", "penetration_test_current"),
    ("UCF-GOV-3", "vulnerability_remediation_sla"),
    ("UCF-GOV-7", "incident_response_tested"),
    ("UCF-GOV-8", "security_incident_tracked"),
    ("UCF-PHY-1", "physical_access_controlled"),
    ("UCF-PHY-2", "visitor_access_logged"),
    ("UCF-HRS-4", "termination_access_revoked"),
    ("UCF-HRS-5", "role_change_access_reviewed"),
    ("UCF-HRS-6", "security_clearance_verified"),
    ("UCF-AI-1", "ai_model_inventory_current"),
    ("UCF-AI-2", "shadow_ai_detected"),
]

for _ctrl, _assertion in _UCF_NEW_BINDINGS:
    engine.bind_control("ucf", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Remediation guidance for new assertions
# ---------------------------------------------------------------------------

engine.set_remediation(
    "tls_version_current",
    {
        "summary": "Upgrade all endpoints to TLS 1.2 or higher.",
        "steps": [
            "Identify endpoints using TLS 1.0 or 1.1 via SSL Labs or cloud config",
            "Update load balancer security policies to enforce TLS 1.2+",
            "Configure Cloudflare minimum TLS version to 1.2",
            "Test client compatibility before disabling older protocols",
        ],
        "console_path": "Load Balancer > Listeners > SSL Policy",
    },
)

engine.set_remediation(
    "network_segmentation_enforced",
    {
        "summary": "Implement network segmentation with dedicated VPCs/VNets and private subnets.",
        "steps": [
            "Design network architecture with separate VPCs for each environment",
            "Create private subnets for application and database tiers",
            "Implement VPC peering or transit gateway with least-privilege routing",
            "Deploy network security groups to restrict inter-segment traffic",
        ],
        "console_path": "VPC > Subnets",
    },
)

engine.set_remediation(
    "waf_enabled",
    {
        "summary": "Enable WAF on all web-facing resources.",
        "steps": [
            "Deploy AWS WAF, Azure WAF, or Cloudflare WAF on internet-facing endpoints",
            "Enable managed rule sets (OWASP Core, Bot Management)",
            "Configure custom rules for application-specific protections",
            "Set WAF to block mode after tuning in count/log mode",
        ],
        "console_path": "WAF > Web ACLs",
    },
)

engine.set_remediation(
    "least_privilege_enforced",
    {
        "summary": "Remove overprivileged IAM policies and enforce least privilege.",
        "steps": [
            "Audit IAM policies for wildcard (*) permissions using IAM Access Analyzer",
            "Replace AdministratorAccess with task-specific policies",
            "Implement permission boundaries for developer roles",
            "Enable IAM Access Analyzer to identify unused permissions",
        ],
        "console_path": "IAM > Access Analyzer",
    },
)

engine.set_remediation(
    "inactive_accounts_disabled",
    {
        "summary": "Disable or remove accounts inactive for 90+ days.",
        "steps": [
            "Generate credential report to identify inactive accounts",
            "Verify with managers before disabling accounts",
            "Disable accounts and remove access keys",
            "Automate inactive account detection with Lambda or IdP rules",
        ],
        "console_path": "IAM > Credential Report",
    },
)

engine.set_remediation(
    "patch_management_current",
    {
        "summary": "Apply security patches within SLA (30 days critical, 90 days high).",
        "steps": [
            "Review missing patches in vulnerability scanner dashboard",
            "Prioritize critical and high severity patches",
            "Deploy patches through MDM (Intune/Jamf) or WSUS",
            "Verify patch installation and reboot if required",
        ],
        "console_path": "Intune > Software Updates",
    },
)

engine.set_remediation(
    "incident_response_tested",
    {
        "summary": "Conduct an incident response drill or tabletop exercise annually.",
        "steps": [
            "Schedule tabletop exercise with security team and stakeholders",
            "Select scenario based on current threat landscape",
            "Document lessons learned and action items",
            "Update IR plan based on exercise findings",
        ],
        "console_path": "GRC Platform > IR Plan",
    },
)

engine.set_remediation(
    "vendor_risk_assessed",
    {
        "summary": "Conduct annual risk assessments for all critical vendors.",
        "steps": [
            "Maintain vendor inventory with criticality tiers",
            "Request SOC 2 reports or security questionnaires from critical vendors",
            "Review SecurityScorecard ratings and track trends",
            "Document risk acceptance for vendors below threshold",
        ],
        "console_path": "Vendor Risk Management Portal",
    },
)

engine.set_remediation(
    "disaster_recovery_tested",
    {
        "summary": "Test disaster recovery procedures at least annually.",
        "steps": [
            "Schedule DR test with infrastructure and application teams",
            "Execute failover to DR region/site",
            "Measure actual RTO and RPO against targets",
            "Document results and update runbooks",
        ],
        "console_path": "DR Management > Test Schedule",
    },
)

engine.set_remediation(
    "ai_model_inventory_current",
    {
        "summary": "Register all AI models in the model inventory with risk classifications.",
        "steps": [
            "Enumerate all AI/ML models in production and development",
            "Register each model with purpose, owner, and data sources",
            "Classify risk level per EU AI Act / ISO 42001 criteria",
            "Create model cards documenting performance and limitations",
        ],
        "console_path": "MLflow > Model Registry",
    },
)

engine.set_remediation(
    "shadow_ai_detected",
    {
        "summary": "Block or monitor unauthorized AI API usage.",
        "steps": [
            "Configure CASB/proxy to detect AI API domains (api.openai.com, api.anthropic.com)",
            "Create URL filtering rules in Zscaler/Netskope for AI services",
            "Establish approved AI tools policy and communicate to organization",
            "Redirect users to sanctioned AI platforms with enterprise governance",
        ],
        "console_path": "Zscaler > URL & Cloud App Control",
    },
)
