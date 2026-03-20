"""Normalized data assembler for OPA compliance evaluation.

Transforms FindingData and RawEventData into the ``normalized_data``
document that Rego policies expect as ``input.normalized_data``.

Each source/event_type pair has a registered assembler function that
knows how to extract the right fields from raw_data and finding detail.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from warlock.normalizers.base import FindingData
from warlock.connectors.base import RawEventData

log = logging.getLogger(__name__)


# Type alias for assembler functions
# Takes (findings_for_event_type, raw_events_for_event_type) -> partial normalized_data dict
AssemblerFn = Callable[[list[FindingData], list[RawEventData]], dict[str, Any]]


class NormalizedDataAssembler:
    """Builds the full normalized_data document from findings and raw events.

    Registered assembler functions transform source-specific data into
    the common schema expected by Rego policies.
    """

    def __init__(self) -> None:
        # (source, event_type) -> assembler_fn
        self._assemblers: dict[tuple[str, str], AssemblerFn] = {}
        self._register_defaults()

    def register(self, source: str, event_type: str, fn: AssemblerFn) -> None:
        """Register an assembler for a (source, event_type) pair."""
        self._assemblers[(source, event_type)] = fn

    def assemble(
        self,
        findings: list[FindingData],
        raw_events: list[RawEventData],
    ) -> dict[str, Any]:
        """Build the full normalized_data document.

        Groups findings and raw events by (source, event_type), runs
        registered assemblers, and deep-merges the results.
        """
        # Group findings by (source, event_type)
        findings_by_type: dict[tuple[str, str], list[FindingData]] = {}
        for f in findings:
            key = (f.source, getattr(f, "event_type", ""))
            # FindingData doesn't have event_type directly -- infer from resource_type
            # We'll match via raw events instead
            findings_by_type.setdefault(key, []).append(f)

        # Group raw events by (source, event_type)
        raw_by_type: dict[tuple[str, str], list[RawEventData]] = {}
        for r in raw_events:
            key = (r.source, r.event_type)
            raw_by_type.setdefault(key, []).append(r)

        # Also group findings by raw_event_id for lookup
        findings_by_raw_id: dict[str, list[FindingData]] = {}
        for f in findings:
            if f.raw_event_id:
                findings_by_raw_id.setdefault(f.raw_event_id, []).append(f)

        # Build the document
        doc: dict[str, Any] = {
            "users": [],
            "root_account": {},
            "password_policy": {},
            "security_groups": [],
            "cloudtrail": {},
            "guardduty_enabled": False,
            "storage_buckets": [],
            "config": {},
            "password_policies": [],
            "endpoints": [],
            "devices": [],
            "detections": [],
            "hr_records": [],
            "background_checks": [],
            "training": {},
            "phishing": {},
            "policies": {},
            "change_management": {},
            "incidents": [],
            "organization": {},
        }

        # Run assemblers for each (source, event_type)
        for key, raw_list in raw_by_type.items():
            assembler = self._assemblers.get(key)
            if assembler is not None:
                # Gather findings for these raw events
                type_findings: list[FindingData] = []
                for r in raw_list:
                    type_findings.extend(findings_by_raw_id.get(r.id, []))
                try:
                    partial = assembler(type_findings, raw_list)
                    _deep_merge(doc, partial)
                except Exception:
                    log.exception("Assembler failed for %s", key)
            else:
                # Generic fallback: passthrough finding details
                for r in raw_list:
                    for f in findings_by_raw_id.get(r.id, []):
                        _deep_merge(doc, f.detail)

        return doc

    # ------------------------------------------------------------------
    # Default assembler registrations
    # ------------------------------------------------------------------

    def _register_defaults(self) -> None:
        """Register assemblers for all major sources."""

        # ---- AWS ----
        self.register("aws", "iam_credential_report", _assemble_aws_credential_report)
        self.register("aws", "iam_password_policy", _assemble_aws_password_policy)
        self.register("aws", "ec2_security_groups", _assemble_aws_security_groups)
        self.register("aws", "cloudtrail_trails", _assemble_aws_cloudtrail)
        self.register("aws", "guardduty_detectors", _assemble_aws_guardduty)
        self.register("aws", "s3_buckets", _assemble_aws_s3)
        self.register("aws", "config_recorders", _assemble_aws_config)

        # ---- Okta ----
        self.register("okta", "okta_users", _assemble_okta_users)
        self.register("okta", "okta_policies", _assemble_okta_policies)

        # ---- CrowdStrike ----
        self.register("crowdstrike", "falcon_devices", _assemble_crowdstrike_devices)
        self.register("crowdstrike", "falcon_detections", _assemble_crowdstrike_detections)

        # ---- Workday ----
        self.register("workday", "workday_employees", _assemble_workday_employees)

        # ---- KnowBe4 ----
        self.register("knowbe4", "kb4_training_enrollments", _assemble_kb4_training)
        self.register("knowbe4", "kb4_phishing_results", _assemble_kb4_phishing)

        # ---- Confluence ----
        self.register("confluence", "confluence_pages", _assemble_confluence_pages)

        # ---- ServiceNow ----
        self.register("servicenow", "snow_change_requests", _assemble_snow_changes)
        self.register("servicenow", "snow_incidents", _assemble_snow_incidents)


# ---------------------------------------------------------------------------
# AWS assemblers
# ---------------------------------------------------------------------------


def _assemble_aws_credential_report(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform IAM credential report into users[] and root_account."""
    users = []
    root_account: dict[str, Any] = {}

    for f in findings:
        detail = f.detail
        username = detail.get("user", "")
        if username == "<root_account>":
            root_account = {
                "access_keys_present": (
                    detail.get("access_key_1_active", False)
                    or detail.get("access_key_2_active", False)
                ),
                "mfa_enabled": detail.get("mfa_active", False),
            }
        else:
            users.append(
                {
                    "username": username,
                    "mfa_enabled": detail.get("mfa_active", False),
                    "password_enabled": detail.get("password_enabled", False),
                    "access_keys": [
                        k
                        for k in [
                            {"status": "Active", "last_used_days": 0}
                            if detail.get("access_key_1_active")
                            else None,
                            {"status": "Active", "last_used_days": 0}
                            if detail.get("access_key_2_active")
                            else None,
                        ]
                        if k is not None
                    ],
                    "last_activity": "",
                    "groups": [],
                    "policies": [],
                }
            )

    return {"users": users, "root_account": root_account, "total_users": len(users)}


def _assemble_aws_password_policy(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform IAM password policy into password_policy."""
    for r in raw_events:
        policy = r.raw_data.get("response", {}).get(
            "PasswordPolicy", r.raw_data.get("response", {})
        )
        return {
            "password_policy": {
                "min_length": policy.get("MinimumPasswordLength", 0),
                "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                "require_numbers": policy.get("RequireNumbers", False),
                "require_symbols": policy.get("RequireSymbols", False),
                "max_age_days": policy.get("MaxPasswordAge", 0),
                "password_reuse_prevention": policy.get("PasswordReusePrevention", 0),
            }
        }
    return {}


def _assemble_aws_security_groups(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform EC2 security groups."""
    sgs = []
    for f in findings:
        sg = f.detail.get("security_group", f.detail)
        sgs.append(
            {
                "group_id": sg.get("GroupId", f.resource_id),
                "group_name": sg.get("GroupName", f.resource_name),
                "ingress_rules": sg.get("IpPermissions", []),
                "egress_rules": sg.get("IpPermissionsEgress", []),
                "issues": f.detail.get("issues", []),
            }
        )
    return {"security_groups": sgs}


def _assemble_aws_cloudtrail(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform CloudTrail trail data."""
    trails = []
    for f in findings:
        trail = f.detail.get("trail", f.detail)
        trails.append(
            {
                "name": trail.get("Name", f.resource_name),
                "is_multi_region": trail.get("IsMultiRegionTrail", False),
                "log_validation": trail.get("LogFileValidationEnabled", False),
                "is_logging": True,
            }
        )
    enabled = len(trails) > 0
    multi_region = any(t.get("is_multi_region") for t in trails)
    return {
        "cloudtrail": {
            "enabled": enabled,
            "trails": trails,
            "multi_region": multi_region,
        }
    }


def _assemble_aws_guardduty(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform GuardDuty detector data."""
    for f in findings:
        detectors = f.detail.get("detectors", [])
        return {"guardduty_enabled": len(detectors) > 0}
    return {"guardduty_enabled": False}


def _assemble_aws_s3(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform S3 bucket data."""
    buckets = []
    for f in findings:
        buckets.append(
            {
                "name": f.resource_name,
                "arn": f.resource_id,
                "encryption": f.detail.get("ServerSideEncryptionConfiguration", {}),
                "public_access_block": f.detail.get("PublicAccessBlockConfiguration", {}),
                "versioning": f.detail.get("Versioning", {}),
            }
        )
    return {"storage_buckets": buckets}


def _assemble_aws_config(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform AWS Config recorder data."""
    recorders = []
    for f in findings:
        rec = f.detail.get("recorder", f.detail)
        recorders.append(
            {
                "name": rec.get("name", f.resource_name),
                "all_supported": rec.get("recordingGroup", {}).get("allSupported", False),
            }
        )
    enabled = len(recorders) > 0
    return {
        "config": {
            "enabled": enabled,
            "recorders": recorders,
        }
    }


# ---------------------------------------------------------------------------
# Okta assemblers
# ---------------------------------------------------------------------------


def _assemble_okta_users(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Merge Okta user data into users[] (MFA status, last login)."""
    users = []
    for f in findings:
        detail = f.detail
        users.append(
            {
                "username": detail.get("login", detail.get("email", f.resource_name)),
                "mfa_enabled": detail.get("mfa_status", "INACTIVE") == "ACTIVE",
                "last_login": detail.get("lastLogin", ""),
                "status": detail.get("status", ""),
                "access_keys": [],
                "last_activity": detail.get("lastLogin", ""),
                "groups": [],
                "policies": [],
            }
        )
    return {"users": users}


def _assemble_okta_policies(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform Okta policies into password_policies[]."""
    policies = []
    for f in findings:
        policies.append(f.detail)
    return {"password_policies": policies}


# ---------------------------------------------------------------------------
# CrowdStrike assemblers
# ---------------------------------------------------------------------------


def _assemble_crowdstrike_devices(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform Falcon device data into endpoints[] and devices[]."""
    endpoints = []
    devices = []
    for f in findings:
        detail = f.detail
        entry = {
            "device_id": detail.get("device_id", f.resource_id),
            "hostname": detail.get("hostname", f.resource_name),
            "platform": detail.get("platform_name", ""),
            "os_version": detail.get("os_version", ""),
            "agent_version": detail.get("agent_version", ""),
            "status": detail.get("status", ""),
            "last_seen": detail.get("last_seen", ""),
        }
        endpoints.append(entry)
        devices.append(entry)
    return {"endpoints": endpoints, "devices": devices}


def _assemble_crowdstrike_detections(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform Falcon detections."""
    detections = []
    for f in findings:
        detections.append(
            {
                "detection_id": f.detail.get("detection_id", f.resource_id),
                "severity": f.severity,
                "status": f.detail.get("status", ""),
                "type": f.detail.get("type", ""),
                "hostname": f.detail.get("hostname", ""),
            }
        )
    return {"detections": detections}


# ---------------------------------------------------------------------------
# Workday assemblers
# ---------------------------------------------------------------------------


def _assemble_workday_employees(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform Workday employee data."""
    hr_records = []
    background_checks = []
    for f in findings:
        detail = f.detail
        hr_records.append(
            {
                "employee_id": detail.get("employee_id", f.resource_id),
                "name": detail.get("name", f.resource_name),
                "status": detail.get("status", ""),
                "hire_date": detail.get("hire_date", ""),
                "termination_date": detail.get("termination_date", ""),
            }
        )
        if detail.get("background_check"):
            background_checks.append(
                {
                    "employee_id": detail.get("employee_id", f.resource_id),
                    "status": detail["background_check"].get("status", ""),
                    "completed_date": detail["background_check"].get("completed_date", ""),
                }
            )
    return {"hr_records": hr_records, "background_checks": background_checks}


# ---------------------------------------------------------------------------
# KnowBe4 assemblers
# ---------------------------------------------------------------------------


def _assemble_kb4_training(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform KnowBe4 training enrollment data."""
    enrollments = []
    for f in findings:
        enrollments.append(f.detail)
    total = len(enrollments)
    completed = sum(1 for e in enrollments if e.get("status") == "Completed")
    return {
        "training": {
            "total_enrollments": total,
            "completed": completed,
            "completion_rate": completed / total if total > 0 else 0.0,
            "enrollments": enrollments,
        }
    }


def _assemble_kb4_phishing(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform KnowBe4 phishing simulation results."""
    results = []
    for f in findings:
        results.append(f.detail)
    total = len(results)
    clicked = sum(1 for r in results if r.get("clicked", False))
    return {
        "phishing": {
            "total_tests": total,
            "clicked": clicked,
            "click_rate": clicked / total if total > 0 else 0.0,
            "results": results,
        }
    }


# ---------------------------------------------------------------------------
# Confluence assembler
# ---------------------------------------------------------------------------


def _assemble_confluence_pages(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Map Confluence page titles to governance document presence."""
    policies: dict[str, Any] = {}

    # Map well-known page titles to policy presence
    title_map = {
        "information security policy": "information_security_policy",
        "acceptable use policy": "acceptable_use_policy",
        "access control policy": "access_control_policy",
        "incident response plan": "incident_response_plan",
        "business continuity plan": "business_continuity_plan",
        "data classification policy": "data_classification_policy",
        "privacy policy": "privacy_policy",
        "change management policy": "change_management_policy",
    }

    for f in findings:
        title = f.detail.get("title", f.resource_name).lower()
        for keyword, policy_key in title_map.items():
            if keyword in title:
                policies[policy_key] = {
                    "exists": True,
                    "title": f.detail.get("title", f.resource_name),
                    "last_updated": f.detail.get("lastUpdated", ""),
                    "approved": f.detail.get("status", "") == "current",
                    "communicated": True,
                    "last_review_days": f.detail.get("days_since_update", 0),
                }

    return {"policies": policies}


# ---------------------------------------------------------------------------
# ServiceNow assemblers
# ---------------------------------------------------------------------------


def _assemble_snow_changes(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform ServiceNow change request data."""
    changes = []
    for f in findings:
        changes.append(
            {
                "number": f.detail.get("number", f.resource_id),
                "state": f.detail.get("state", ""),
                "type": f.detail.get("type", ""),
                "approval": f.detail.get("approval", ""),
                "risk": f.detail.get("risk", ""),
            }
        )
    total = len(changes)
    approved = sum(1 for c in changes if c.get("approval") == "approved")
    return {
        "change_management": {
            "total_changes": total,
            "approved": approved,
            "approval_rate": approved / total if total > 0 else 0.0,
            "changes": changes,
        }
    }


def _assemble_snow_incidents(
    findings: list[FindingData],
    raw_events: list[RawEventData],
) -> dict[str, Any]:
    """Transform ServiceNow incident data."""
    incidents = []
    for f in findings:
        incidents.append(
            {
                "number": f.detail.get("number", f.resource_id),
                "state": f.detail.get("state", ""),
                "severity": f.detail.get("severity", f.severity),
                "category": f.detail.get("category", ""),
            }
        )
    return {"incidents": incidents}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deep_merge(base: dict, overlay: dict) -> None:
    """Merge overlay into base, concatenating lists and recursing dicts."""
    for key, value in overlay.items():
        if key in base:
            if isinstance(base[key], dict) and isinstance(value, dict):
                _deep_merge(base[key], value)
            elif isinstance(base[key], list) and isinstance(value, list):
                base[key].extend(value)
            else:
                base[key] = value
        else:
            base[key] = value
