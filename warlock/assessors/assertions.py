"""Assertion library for compliance checks.

Registers deterministic assertion functions with the singleton engine.
Each assertion takes (detail: dict, raw_data: dict) -> (bool, list[str])
and is bound to relevant NIST 800-53 controls.
"""

from __future__ import annotations

from datetime import datetime, timezone
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
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
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
            reasons.append(f"Okta user {detail.get('login', detail.get('email', 'unknown'))} — no MFA factors enrolled")
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
    user_id = detail.get("user") or detail.get("login") or detail.get("userPrincipalName") or detail.get("displayName")
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
            reasons.append(f"Security group {sg_id} has unrestricted ingress: {', '.join(open_ports)}")
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
            if (props.get("access") == "Allow"
                    and props.get("direction") == "Inbound"
                    and props.get("sourceAddressPrefix") in ("*", "0.0.0.0/0")):
                reasons.append(f"Azure NSG rule {props.get('name', '?')} allows unrestricted inbound")

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
            reasons.append(f"S3 bucket {detail.get('Name', '?')} — no encryption configuration found")

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
        if not isinstance(bucket_encryption, dict) or not bucket_encryption.get("defaultKmsKeyName"):
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
    public_access = detail.get("PublicAccessBlockConfiguration", detail.get("public_access_block", {}))
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
    hostname = detail.get("hostname") or detail.get("computerDnsName") or detail.get("computer_name") or "unknown"

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
        auto_mgmt = secret_mgmt.get("automaticManagementEnabled", secret_mgmt.get("automatic_management"))
        if auto_mgmt is False:
            account_name = detail.get("name") or detail.get("userName") or "unknown"
            reasons.append(f"Privileged account {account_name} — automatic management disabled")
            return False, reasons
        last_modified = secret_mgmt.get("lastModifiedTime") or secret_mgmt.get("last_modified")
        if last_modified:
            days = _days_since(str(last_modified))
            if days is not None and days > 90:
                account_name = detail.get("name") or detail.get("userName") or "unknown"
                reasons.append(f"Privileged account {account_name} — password not rotated in {days} days")
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
    ("A.5.7", "guardduty_enabled"),          # Threat intelligence
    ("A.5.15", "mfa_enabled"),               # Access control
    ("A.5.16", "access_reviews_current"),     # Identity management
    ("A.5.17", "password_policy_compliant"),  # Authentication information
    ("A.5.23", "config_recorder_enabled"),    # Cloud services
    ("A.5.25", "siem_monitoring_active"),     # Assessment of security events
    ("A.5.26", "siem_monitoring_active"),     # Response to incidents
    ("A.6.5", "access_reviews_current"),      # After termination
    ("A.8.1", "device_compliant"),             # User endpoint devices
    ("A.8.2", "privileged_access_managed"),   # Privileged access rights
    ("A.8.5", "mfa_enabled"),                 # Secure authentication
    ("A.8.7", "endpoint_protection_active"),  # Protection against malware
    ("A.8.8", "vulnerability_scan_current"),  # Management of technical vulnerabilities
    ("A.8.9", "config_recorder_enabled"),     # Configuration management
    ("A.8.15", "cloudtrail_enabled"),         # Logging
    ("A.8.16", "siem_monitoring_active"),     # Monitoring activities
    ("A.8.20", "no_open_security_groups"),    # Networks security
    ("A.8.22", "no_open_security_groups"),    # Segregation of networks
    ("A.8.24", "encryption_at_rest"),         # Use of cryptography
]

for _ctrl, _assertion in _ISO27001_BINDINGS:
    engine.bind_control("iso_27001", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — ISO 27701
# ---------------------------------------------------------------------------

_ISO27701_BINDINGS: list[tuple[str, str]] = [
    ("CL6.5.2.1", "mfa_enabled"),            # Access control
    ("CL6.5.3.1", "encryption_at_rest"),      # Cryptographic controls
    ("CL6.6.2.1", "cloudtrail_enabled"),      # Event logging
    ("CL6.8.2.1", "no_open_security_groups"), # Network security
    ("CL6.9.3.1", "encryption_at_rest"),      # Protection of records
    ("A.7.4.5", "encryption_at_rest"),        # PII de-identification and deletion
    ("A.7.4.9", "encryption_at_rest"),        # PII transmission controls
    ("B.8.4.3", "encryption_at_rest"),        # Processor PII transmission
]

for _ctrl, _assertion in _ISO27701_BINDINGS:
    engine.bind_control("iso_27701", _ctrl, _assertion)


# ---------------------------------------------------------------------------
# Control bindings — ISO 42001
# ---------------------------------------------------------------------------

_ISO42001_BINDINGS: list[tuple[str, str]] = [
    ("A.6.2.12", "siem_monitoring_active"),      # AI system operation and monitoring
    ("A.9.3", "mfa_enabled"),                    # Misuse prevention — access
    ("A.9.4", "access_reviews_current"),         # Human oversight — reviews
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
            reasons.append(f"Training campaign '{campaign}' completion at {completion_pct}% (target: 95%)")
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
        reasons.append(f"Open {severity} code vulnerability: {title}" + (f" in {pkg}" if pkg else ""))
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
    last_updated = detail.get("last_updated") or detail.get("modified_date") or detail.get("updated_at")
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
# Remediation guidance
# ---------------------------------------------------------------------------

engine.set_remediation("mfa_enabled", {
    "summary": "Enable multi-factor authentication for all users with console/interactive access.",
    "steps": [
        "Identify all users without MFA enabled",
        "Enforce MFA via IAM policy, Okta sign-on policy, or Entra ID Conditional Access",
        "Require hardware security keys or authenticator apps (avoid SMS)",
        "Verify MFA enrollment via credential report or IdP dashboard",
    ],
    "console_path": "IAM > Users > Security credentials > MFA",
})

engine.set_remediation("no_root_access_keys", {
    "summary": "Remove all access keys from the root/admin account.",
    "steps": [
        "Sign in as the root user",
        "Navigate to Security Credentials",
        "Delete all active access keys",
        "Use IAM users or roles for programmatic access instead",
    ],
    "console_path": "IAM > Root user > Security credentials",
})

engine.set_remediation("cloudtrail_enabled", {
    "summary": "Enable CloudTrail with multi-region logging and log file validation.",
    "steps": [
        "Create or update a trail to cover all regions",
        "Enable log file validation",
        "Configure S3 bucket with appropriate retention and encryption",
        "Enable CloudWatch Logs integration for real-time alerting",
    ],
    "console_path": "CloudTrail > Trails",
})

engine.set_remediation("guardduty_enabled", {
    "summary": "Enable GuardDuty (or equivalent threat detection) in all regions.",
    "steps": [
        "Enable GuardDuty in each AWS region",
        "Configure a delegated administrator for multi-account setups",
        "Enable S3 protection and EKS audit log monitoring",
        "Set up SNS notifications for high-severity findings",
    ],
    "console_path": "GuardDuty > Settings",
})

engine.set_remediation("securityhub_enabled", {
    "summary": "Enable AWS SecurityHub for centralized security findings.",
    "steps": [
        "Enable SecurityHub in each region",
        "Enable AWS Foundational Security Best Practices standard",
        "Enable CIS AWS Foundations Benchmark standard",
        "Configure cross-region aggregation",
    ],
    "console_path": "SecurityHub > Settings",
})

engine.set_remediation("no_open_security_groups", {
    "summary": "Restrict security group ingress rules to remove unrestricted access on sensitive ports.",
    "steps": [
        "Identify security groups with 0.0.0.0/0 ingress on sensitive ports (22, 3389, DB ports)",
        "Replace broad CIDR rules with specific IP ranges or security group references",
        "Use AWS Systems Manager Session Manager instead of SSH where possible",
        "Implement network segmentation with VPC endpoints",
    ],
    "console_path": "VPC > Security Groups",
})

engine.set_remediation("encryption_at_rest", {
    "summary": "Enable encryption at rest for all storage resources.",
    "steps": [
        "Enable default encryption on S3 buckets (SSE-S3 or SSE-KMS)",
        "Enable encryption for EBS volumes, RDS instances, and DynamoDB tables",
        "For Azure, verify Storage Service Encryption is enabled",
        "For GCP, verify Cloud KMS keys are configured or Google-managed encryption is active",
    ],
    "console_path": "S3 > Bucket > Properties > Default encryption",
})

engine.set_remediation("password_policy_compliant", {
    "summary": "Update the password policy to meet compliance requirements.",
    "steps": [
        "Set minimum password length to 14 or more characters",
        "Require uppercase, lowercase, numbers, and symbols",
        "Configure password expiration (90 days recommended)",
        "Enable password reuse prevention (24 passwords)",
    ],
    "console_path": "IAM > Account settings > Password policy",
})

engine.set_remediation("config_recorder_enabled", {
    "summary": "Enable AWS Config recorder to track all resource configurations.",
    "steps": [
        "Create a configuration recorder that records all resource types",
        "Set up a delivery channel to an S3 bucket",
        "Enable AWS Config rules for continuous compliance evaluation",
        "Consider using conformance packs for framework-aligned rule sets",
    ],
    "console_path": "AWS Config > Settings",
})

engine.set_remediation("no_public_storage", {
    "summary": "Remove public access from all storage buckets and accounts.",
    "steps": [
        "Enable S3 Block Public Access at the account level",
        "Review and remove bucket policies granting public access",
        "Remove ACLs granting access to AllUsers or AuthenticatedUsers",
        "For Azure, disable public blob access on storage accounts",
    ],
    "console_path": "S3 > Block Public Access settings",
})

engine.set_remediation("endpoint_protection_active", {
    "summary": "Ensure all endpoints have active EDR agents.",
    "steps": [
        "Identify endpoints with offline or inactive agents",
        "Reinstall or restart agents on affected endpoints",
        "Verify sensor policies enforce prevention mode",
        "Implement automated alerting for agent health degradation",
    ],
    "console_path": "EDR Console > Host Management",
})

engine.set_remediation("vulnerability_scan_current", {
    "summary": "Ensure vulnerability scans are performed regularly (at least every 30 days).",
    "steps": [
        "Configure scheduled scans for all assets",
        "Verify scan coverage includes all network segments",
        "Remediate critical and high vulnerabilities within SLA",
        "Review scan exclusions to minimize blind spots",
    ],
    "console_path": "Vulnerability Scanner > Scan Policies",
})

engine.set_remediation("privileged_access_managed", {
    "summary": "Ensure all privileged accounts are managed through PAM with automatic rotation.",
    "steps": [
        "Onboard all privileged accounts to CyberArk (or equivalent PAM)",
        "Enable automatic password management and rotation",
        "Configure session recording for privileged sessions",
        "Review and remediate non-compliant accounts",
    ],
    "console_path": "CyberArk > Accounts",
})

engine.set_remediation("access_reviews_current", {
    "summary": "Complete all outstanding access certification campaigns.",
    "steps": [
        "Identify overdue or expired certification campaigns",
        "Escalate incomplete certifications to reviewers and managers",
        "Revoke access for uncertified entitlements",
        "Schedule recurring certification campaigns on a quarterly basis",
    ],
    "console_path": "SailPoint > Certifications",
})

engine.set_remediation("siem_monitoring_active", {
    "summary": "Ensure SIEM has active detection rules and connected data sources.",
    "steps": [
        "Review and enable detection rules aligned to MITRE ATT&CK",
        "Verify all critical data sources are connected and ingesting",
        "Configure alerting thresholds and notification channels",
        "Test detection rules with simulated attack scenarios",
    ],
    "console_path": "SIEM > Detection Rules",
})

engine.set_remediation("background_check_completed", {
    "summary": "Ensure all employees have completed background checks before or shortly after hire.",
    "steps": [
        "Identify employees without completed background checks",
        "Initiate background check process through HR/Workday",
        "Set automated triggers for new hire background checks",
        "Track completion status and follow up on delays",
    ],
    "console_path": "Workday > Staffing > Background Checks",
})

engine.set_remediation("employment_agreement_signed", {
    "summary": "Ensure all employees have signed employment agreements and NDAs.",
    "steps": [
        "Identify employees without signed agreements",
        "Send agreement documents for e-signature",
        "Configure onboarding workflow to require signatures before system access",
        "Audit quarterly for gaps",
    ],
    "console_path": "Workday > Documents > Agreements",
})

engine.set_remediation("change_request_approved", {
    "summary": "Ensure all changes have documented approval and rollback plans.",
    "steps": [
        "Review change management policy for approval requirements",
        "Configure ServiceNow to require approval before implementation",
        "Add rollback plan as required field on change request form",
        "Audit emergency changes for post-implementation review",
    ],
    "console_path": "ServiceNow > Change Management",
})

engine.set_remediation("training_completion_rate", {
    "summary": "Ensure security awareness training completion meets organizational targets.",
    "steps": [
        "Identify users with overdue or incomplete training",
        "Send reminder notifications through KnowBe4",
        "Escalate chronic non-completers to management",
        "Configure automated enrollment for new hires within 30 days",
    ],
    "console_path": "KnowBe4 > Training > Campaigns",
})

engine.set_remediation("phishing_failure_rate", {
    "summary": "Reduce phishing simulation click rate below organizational threshold.",
    "steps": [
        "Review phishing simulation results by department",
        "Provide targeted training for high-risk users",
        "Increase simulation frequency for repeat offenders",
        "Report metrics to management quarterly",
    ],
    "console_path": "KnowBe4 > Phishing > Security Tests",
})

engine.set_remediation("no_critical_code_vulns", {
    "summary": "Remediate critical and high severity code vulnerabilities.",
    "steps": [
        "Triage critical/high findings in Snyk dashboard",
        "Apply available fixes and upgrade vulnerable packages",
        "If no fix available, evaluate compensating controls or risk acceptance",
        "Configure CI/CD to block merges with critical vulnerabilities",
    ],
    "console_path": "Snyk > Projects > Issues",
})

engine.set_remediation("backup_job_successful", {
    "summary": "Ensure backup jobs complete successfully and RPO targets are met.",
    "steps": [
        "Investigate failed backup job errors",
        "Verify backup storage capacity and connectivity",
        "Test restore from most recent backup",
        "Configure alerting for backup failures",
    ],
    "console_path": "Veeam > Jobs > Last Session",
})

engine.set_remediation("device_compliant", {
    "summary": "Ensure all managed devices meet compliance policies.",
    "steps": [
        "Review non-compliant devices in Intune portal",
        "Enable disk encryption (BitLocker/FileVault) on non-encrypted devices",
        "Push OS updates to devices with outdated versions",
        "Configure conditional access to block non-compliant devices",
    ],
    "console_path": "Intune > Devices > Compliance",
})

engine.set_remediation("policy_reviewed_within_year", {
    "summary": "Ensure all security policies and procedures are reviewed annually.",
    "steps": [
        "Identify documents not reviewed within 365 days",
        "Assign document owners to review and update content",
        "Update revision date and approval signatures",
        "Schedule recurring annual review calendar reminders",
    ],
    "console_path": "Confluence > Space > Pages",
})

engine.set_remediation("dlp_policies_active", {
    "summary": "Ensure DLP policies are enabled and actively monitoring data flows.",
    "steps": [
        "Review disabled DLP policies in Purview compliance portal",
        "Enable policies or update if requirements have changed",
        "Verify policy conditions and actions are correctly configured",
        "Test policies with synthetic sensitive data",
    ],
    "console_path": "Microsoft Purview > Data Loss Prevention > Policies",
})
