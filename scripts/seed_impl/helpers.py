"""Shared rich-data generation and vendor-format helpers for demo connectors."""

from __future__ import annotations

import random
import threading

from scripts.seed_impl.constants import NOW

try:
    from scripts.demo_data import (
        generate_auth_logs,
        generate_cloud_instances,
        generate_code_findings,
        generate_container_images,
        generate_devices,
        generate_dns_queries,
        generate_email_events,
        generate_employees,
        generate_endpoints_edr,
        generate_groups,
        generate_iac_misconfigs,
        generate_iam_policies,
        generate_incidents,
        generate_policy_documents,
        generate_security_alerts,
        generate_security_groups,
        generate_storage_buckets,
        generate_terraform_workspaces,
        generate_training_records,
        generate_users,
        generate_vendor_assessments,
        generate_vulnerabilities,
    )
except ImportError:
    from demo_data import (  # type: ignore[no-redef]
        generate_auth_logs,
        generate_cloud_instances,
        generate_code_findings,
        generate_container_images,
        generate_devices,
        generate_dns_queries,
        generate_email_events,
        generate_employees,
        generate_endpoints_edr,
        generate_groups,
        generate_iac_misconfigs,
        generate_iam_policies,
        generate_incidents,
        generate_policy_documents,
        generate_security_alerts,
        generate_security_groups,
        generate_storage_buckets,
        generate_terraform_workspaces,
        generate_training_records,
        generate_users,
        generate_vendor_assessments,
        generate_vulnerabilities,
    )

# Rich demo data — generated once, shared across connectors

RICH_DATA: dict = {}
_RICH_DATA_LOCK = threading.Lock()
_RICH_DATA_READY = False


def _ensure_rich_data():
    """Lazily generate rich data on first use (thread-safe)."""
    global _RICH_DATA_READY
    if _RICH_DATA_READY:
        return
    with _RICH_DATA_LOCK:
        if _RICH_DATA_READY:
            return
        RICH_DATA["users"] = generate_users(200)
        RICH_DATA["groups"] = generate_groups(30)
        RICH_DATA["auth_logs"] = generate_auth_logs(1500)
        RICH_DATA["devices"] = generate_devices(400)
        RICH_DATA["endpoints_edr"] = generate_endpoints_edr(300)
        RICH_DATA["cloud_instances"] = generate_cloud_instances(600)
        RICH_DATA["iam_policies"] = generate_iam_policies(100)
        RICH_DATA["security_groups"] = generate_security_groups(200)
        RICH_DATA["storage_buckets"] = generate_storage_buckets(150)
        RICH_DATA["vulnerabilities"] = generate_vulnerabilities(2600)
        RICH_DATA["code_findings"] = generate_code_findings(1200)
        RICH_DATA["container_images"] = generate_container_images(200)
        RICH_DATA["employees"] = generate_employees(500)
        RICH_DATA["training_records"] = generate_training_records(600)
        RICH_DATA["security_alerts"] = generate_security_alerts(1000)
        RICH_DATA["incidents"] = generate_incidents(80)
        RICH_DATA["vendor_assessments"] = generate_vendor_assessments(60)
        RICH_DATA["policy_documents"] = generate_policy_documents(40)
        RICH_DATA["dns_queries"] = generate_dns_queries(600)
        RICH_DATA["email_events"] = generate_email_events(700)
        RICH_DATA["terraform_workspaces"] = generate_terraform_workspaces(40)
        RICH_DATA["iac_misconfigs"] = generate_iac_misconfigs(200)
        _RICH_DATA_READY = True


def _users_as_okta(users: list[dict]) -> list[dict]:
    """Convert RICH_DATA users to Okta API format."""
    result = []
    for u in users:
        status = (
            "ACTIVE"
            if u["status"] == "active"
            else ("SUSPENDED" if u["status"] == "suspended" else "DEPROVISIONED")
        )
        result.append(
            {
                "id": u["user_id"],
                "status": status,
                "profile": {
                    "login": u["email"],
                    "firstName": u["first_name"],
                    "lastName": u["last_name"],
                },
                "lastLogin": u["last_login"],
            }
        )
    return result


def _users_as_entra(users: list[dict]) -> list[dict]:
    """Convert RICH_DATA users to Entra ID / Microsoft Graph format."""
    result = []
    for u in users:
        account_enabled = u["status"] == "active"
        result.append(
            {
                "id": u["user_id"],
                "displayName": f"{u['first_name']} {u['last_name']}",
                "userPrincipalName": u["email"],
                "accountEnabled": account_enabled,
                "department": u.get("department", ""),
                "createdDateTime": u["created_at"],
                "signInActivity": {"lastSignInDateTime": u["last_login"]},
                "assignedLicenses": [{"skuId": "sku-e5"}],
            }
        )
    return result


def _users_as_cyberark(users: list[dict]) -> list[dict]:
    """Convert RICH_DATA users to CyberArk privileged accounts format."""
    result = []
    for u in users:
        # CyberArk expects lastModifiedTime as epoch seconds
        try:
            from datetime import datetime as _dt

            last_mod_epoch = int(
                _dt.fromisoformat(u["last_login"].replace("+00:00", "+00:00")).timestamp()
            )
        except (ValueError, AttributeError):
            last_mod_epoch = int(NOW.timestamp()) - random.randint(0, 86400 * 90)
        result.append(
            {
                "id": u["user_id"],
                "name": u["username"],
                "address": f"srv-{u['department'].lower()[:3]}.acme.com"
                if u.get("department")
                else "srv.acme.com",
                "userName": u["username"],
                "platformId": random.choice(
                    ["UnixSSH", "WinDomain", "WinServerLocal", "AWSAccessKeys"]
                ),
                "safeName": f"{u.get('department', 'General')}-Accounts",
                "secretManagement": {
                    "automaticManagementEnabled": random.random() > 0.15,
                    "lastModifiedTime": last_mod_epoch,
                },
            }
        )
    return result


def _users_as_sailpoint(users: list[dict]) -> list[dict]:
    """Convert RICH_DATA users to SailPoint identities format."""
    result = []
    for u in users:
        result.append(
            {
                "id": u["user_id"],
                "name": f"{u['first_name']} {u['last_name']}",
                "alias": u["username"],
                "email": u["email"],
                "status": "ACTIVE" if u["status"] == "active" else "INACTIVE",
                "department": u.get("department", ""),
                "isManager": random.random() < 0.15,
                "managerRef": {"name": "Manager"},
                "created": u["created_at"],
                "modified": u["last_login"],
                "attributes": {
                    "lastLogin": u["last_login"],
                    "riskScore": random.randint(0, 100),
                },
            }
        )
    return result


def _auth_logs_as_okta(logs: list[dict]) -> list[dict]:
    """Convert RICH_DATA auth_logs to Okta system log format."""
    result = []
    for log in logs:
        if log["result"] == "success":
            event_type = "user.session.start"
            outcome = "SUCCESS"
        elif log["result"] == "fraud":
            event_type = "user.session.start"
            outcome = "FAILURE"
        else:
            event_type = random.choice(
                [
                    "user.session.start",
                    "user.authentication.auth_via_mfa",
                ]
            )
            outcome = "FAILURE"
        result.append(
            {
                "eventType": event_type,
                "outcome": {"result": outcome},
                "actor": {
                    "displayName": log["email"],
                    "id": log.get("event_id", ""),
                },
            }
        )
    return result


def _vulns_as_crowdstrike(vulns: list[dict]) -> list[dict]:
    """Convert RICH_DATA vulnerabilities to CrowdStrike Spotlight format."""
    result = []
    for v in vulns:
        sev_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
        result.append(
            {
                "id": v["vuln_id"],
                "cve": {
                    "id": v["cve_id"],
                    "base_score_severity": sev_map.get(v["severity"], "Medium"),
                },
                "status": v["status"],
                "host_info": {
                    "hostname": v["affected_resource"],
                    "device_id": f"dev-{v['vuln_id'][-6:]}",
                },
                "app": {
                    "product_name_version": f"{v['package_name']} {v['installed_version']}",
                },
            }
        )
    return result


def _vulns_as_tenable(vulns: list[dict]) -> list[dict]:
    """Convert RICH_DATA vulnerabilities to Tenable export format."""
    sev_num = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    result = []
    for v in vulns:
        result.append(
            {
                "asset": {
                    "hostname": v["affected_resource"],
                    "ipv4": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    "operating_system": random.choice(
                        ["Ubuntu 22.04", "Windows Server 2022", "Amazon Linux 2"]
                    ),
                },
                "plugin": {
                    "id": random.randint(10000, 99999),
                    "name": v["title"],
                    "cvss_base_score": v["cvss_score"],
                    "severity": sev_num.get(v["severity"], 2),
                    "cve": [v["cve_id"]],
                    "solution": f"Upgrade {v['package_name']} to version {v['fixed_version']} or later.",
                    "see_also": [f"https://nvd.nist.gov/vuln/detail/{v['cve_id']}"],
                },
                "severity": v["severity"],
                "state": "open" if v["status"] == "open" else "fixed",
                "first_found": v["first_seen"],
                "last_found": v["last_seen"],
            }
        )
    return result


def _vulns_as_qualys(vulns: list[dict]) -> list[dict]:
    """Convert RICH_DATA vulnerabilities to Qualys host detection format."""
    sev_num = {"critical": 5, "high": 4, "medium": 3, "low": 2}
    result = []
    for v in vulns:
        result.append(
            {
                "QID": random.randint(10000, 99999),
                "HOST": {
                    "IP": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    "DNS": v["affected_resource"],
                    "OS": random.choice(["Linux", "Windows", "macOS"]),
                },
                "VULN": {
                    "TITLE": v["title"],
                    "SEVERITY": sev_num.get(v["severity"], 3),
                    "CVE_ID_LIST": {"CVE_ID": v["cve_id"]},
                    "CVSS_BASE": str(v["cvss_score"]),
                    "SOLUTION": f"Upgrade {v['package_name']} to {v['fixed_version']}",
                    "FIRST_FOUND": v["first_seen"],
                    "LAST_FOUND": v["last_seen"],
                    "STATUS": "Active" if v["status"] == "open" else "Fixed",
                },
            }
        )
    return result


def _vulns_as_wiz(vulns: list[dict]) -> list[dict]:
    """Convert RICH_DATA vulnerabilities to Wiz issues format."""
    result = []
    for v in vulns:
        sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
        result.append(
            {
                "id": v["vuln_id"],
                "sourceRule": {"name": v["title"]},
                "severity": sev_map.get(v["severity"], "MEDIUM"),
                "status": "OPEN" if v["status"] == "open" else "RESOLVED",
                "entitySnapshot": {
                    "type": v["resource_type"],
                    "name": v["affected_resource"],
                    "cloudPlatform": random.choice(["AWS", "Azure", "GCP"]),
                },
                "firstDetectedAt": v["first_seen"],
                "resolvedAt": v["last_seen"] if v["status"] != "open" else None,
            }
        )
    return result


def _endpoints_as_crowdstrike(endpoints: list[dict]) -> list[dict]:
    """Convert RICH_DATA endpoints_edr to CrowdStrike device format."""
    result = []
    for ep in endpoints:
        result.append(
            {
                "device_id": ep["agent_id"],
                "hostname": ep["hostname"],
                "platform_name": ep["platform"],
                "os_version": ep["os_version"],
                "agent_version": ep["agent_version"],
                "status": "normal"
                if ep["status"] == "online"
                else ("contained" if ep["status"] == "degraded" else "offline"),
                "reduced_functionality_mode": "yes" if ep["status"] == "degraded" else "no",
                "device_policies": {
                    "prevention": {"applied": ep["prevention_mode"] == "prevent"},
                },
            }
        )
    return result


def _endpoints_as_defender(endpoints: list[dict]) -> list[dict]:
    """Convert RICH_DATA endpoints_edr to Defender for Endpoint format."""
    result = []
    for ep in endpoints:
        result.append(
            {
                "id": ep["agent_id"],
                "computerDnsName": ep["hostname"],
                "osPlatform": ep["platform"],
                "osVersion": ep["os_version"],
                "healthStatus": "Active" if ep["status"] == "online" else "Inactive",
                "riskScore": random.choice(["Low", "Medium", "High"]),
                "exposureLevel": random.choice(["Low", "Medium", "High"]),
                "onboardingStatus": "Onboarded",
                "lastSeen": ep["last_seen"],
                "avIsSignatureUpToDate": ep["status"] == "online",
            }
        )
    return result


def _endpoints_as_sentinelone(endpoints: list[dict]) -> list[dict]:
    """Convert RICH_DATA endpoints_edr to SentinelOne agent format."""
    result = []
    for ep in endpoints:
        infected = random.random() < 0.05
        result.append(
            {
                "id": ep["agent_id"],
                "computerName": ep["hostname"],
                "osType": ep["platform"].lower(),
                "osName": f"{ep['platform']} {ep['os_version']}",
                "agentVersion": ep["agent_version"],
                "isActive": ep["status"] == "online",
                "infected": infected,
                "networkStatus": "connected" if ep["status"] == "online" else "disconnected",
                "lastActiveDate": ep["last_seen"],
                "encryptedApplications": random.random() > 0.05,
                "firewallEnabled": random.random() > 0.05,
                "isPendingUninstall": False,
                "mitigationMode": "protect" if ep["prevention_mode"] == "prevent" else "detect",
                "threatRebootRequired": False,
            }
        )
    return result


def _endpoints_as_sophos(endpoints: list[dict]) -> list[dict]:
    """Convert RICH_DATA endpoints_edr to Sophos Central format."""
    result = []
    for ep in endpoints:
        health = (
            "good" if ep["status"] == "online" and ep["prevention_mode"] == "prevent" else "bad"
        )
        result.append(
            {
                "id": ep["agent_id"],
                "hostname": ep["hostname"],
                "os": {
                    "name": ep["platform"],
                    "platform": ep["platform"].lower(),
                    "majorVersion": random.randint(10, 14),
                },
                "health": {"overall": health, "threats": {"status": health}},
                "tamperProtectionEnabled": ep["prevention_mode"] == "prevent",
                "associatedPerson": {"viaLogin": f"user-{ep['agent_id'][-6:]}@acme.com"},
                "lastSeenAt": ep["last_seen"],
                "ipv4Addresses": [f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"],
            }
        )
    return result


def _alerts_as_sentinel(alerts: list[dict]) -> list[dict]:
    """Convert RICH_DATA security_alerts to Azure Sentinel incident format."""
    result = []
    sev_map = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
    }
    status_map = {
        "new": "New",
        "investigating": "Active",
        "resolved": "Closed",
        "false_positive": "Closed",
    }
    for a in alerts:
        result.append(
            {
                "id": a["alert_id"],
                "properties": {
                    "title": a["title"],
                    "severity": sev_map.get(a["severity"], "Medium"),
                    "status": status_map.get(a["status"], "New"),
                    "createdTimeUtc": a["detected_at"],
                    "closedTimeUtc": a.get("resolved_at"),
                    "incidentNumber": random.randint(1000, 9999),
                },
            }
        )
    return result


def _alerts_as_splunk(alerts: list[dict]) -> list[dict]:
    """Convert RICH_DATA security_alerts to Splunk notable events format."""
    result = []
    for a in alerts:
        urgency_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }
        result.append(
            {
                "event_id": a["alert_id"],
                "search_name": a["title"],
                "urgency": urgency_map.get(a["severity"], "medium"),
                "status_label": "Resolved"
                if a["status"] == "resolved"
                else ("In Progress" if a["status"] == "investigating" else "New"),
                "time": a["detected_at"],
                "src": a["affected_host"],
                "dest": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "rule_name": a["title"],
            }
        )
    return result


def _alerts_as_elastic(alerts: list[dict]) -> list[dict]:
    """Convert RICH_DATA security_alerts to Elastic Security alert format."""
    result = []
    sev_num = {"critical": 99, "high": 73, "medium": 47, "low": 21, "info": 1}
    for a in alerts:
        result.append(
            {
                "id": a["alert_id"],
                "name": a["title"],
                "severity": a["severity"],
                "risk_score": sev_num.get(a["severity"], 47),
                "status": "closed" if a["status"] in ("resolved", "false_positive") else "open",
                "timestamp": a["detected_at"],
                "host": {"name": a["affected_host"]},
                "threat": {
                    "technique": [{"id": a.get("technique", "T1078"), "name": a["title"]}],
                    "tactic": [{"name": a.get("tactic", "Unknown")}],
                },
            }
        )
    return result


def _devices_as_intune(devices: list[dict]) -> list[dict]:
    """Convert RICH_DATA devices to Intune managed devices format."""
    result = []
    for d in devices:
        result.append(
            {
                "id": d["device_id"],
                "deviceName": d["device_name"],
                "operatingSystem": d["platform"],
                "osVersion": d["os_version"],
                "complianceState": "compliant" if d["is_compliant"] else "noncompliant",
                "isEncrypted": d["is_encrypted"],
                "userPrincipalName": d["user_email"],
                "lastSyncDateTime": d["last_seen"],
                "model": d["model"],
                "serialNumber": d["serial_number"],
                "managedDeviceOwnerType": "company",
            }
        )
    return result


def _devices_as_jamf(devices: list[dict]) -> list[dict]:
    """Convert RICH_DATA devices to Jamf Pro format (macOS/iOS only)."""
    result = []
    for d in devices:
        if d["platform"] not in ("macOS", "iOS"):
            continue
        result.append(
            {
                "id": d["device_id"],
                "general": {
                    "name": d["device_name"],
                    "serial_number": d["serial_number"],
                    "mac_address": f"AA:BB:CC:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
                    "last_contact_time": d["last_seen"],
                    "platform": d["platform"],
                    "os_version": d["os_version"],
                },
                "hardware": {"model": d["model"]},
                "security": {
                    "filevault2_status": "Encrypted" if d["is_encrypted"] else "Not Encrypted",
                    "firewall_enabled": d["firewall_enabled"],
                    "gatekeeper_status": "App Store and identified developers",
                },
            }
        )
    return result


def _devices_as_kandji(devices: list[dict]) -> list[dict]:
    """Convert RICH_DATA devices to Kandji format (macOS/iOS only)."""
    result = []
    for d in devices:
        if d["platform"] not in ("macOS", "iOS"):
            continue
        result.append(
            {
                "device_id": d["device_id"],
                "device_name": d["device_name"],
                "model": d["model"],
                "serial_number": d["serial_number"],
                "platform": d["platform"],
                "os_version": d["os_version"],
                "last_check_in": d["last_seen"],
                "filevault_enabled": d["is_encrypted"],
                "firewall_enabled": d["firewall_enabled"],
                "blueprint_name": random.choice(["Standard macOS", "Engineering", "Executives"]),
                "user": {"email": d["user_email"]},
            }
        )
    return result


def _employees_as_workday(employees: list[dict]) -> list[dict]:
    """Convert RICH_DATA employees to Workday worker format."""
    result = []
    for emp in employees:
        result.append(
            {
                "id": emp["employee_id"],
                "descriptor": f"{emp['first_name']} {emp['last_name']}",
                "status": "Active"
                if emp["status"] == "active"
                else ("Terminated" if emp["status"] == "terminated" else "Leave"),
                "hireDate": emp["start_date"],
                "department": emp["department"],
                "manager": emp.get("manager_email", ""),
                **(
                    {"terminationDate": emp["termination_date"]}
                    if emp.get("termination_date")
                    else {}
                ),
            }
        )
    return result


def _employees_as_bamboohr(employees: list[dict]) -> list[dict]:
    """Convert RICH_DATA employees to BambooHR format."""
    result = []
    for emp in employees:
        result.append(
            {
                "id": int(emp["employee_id"].replace("EMP-", "")) + 7000,
                "displayName": f"{emp['first_name']} {emp['last_name']}",
                "status": "Active" if emp["status"] == "active" else "Inactive",
                "department": emp["department"],
                "jobTitle": emp["title"],
                "hireDate": emp["start_date"],
                "terminationDate": emp.get("termination_date"),
                "supervisor": emp.get("manager_email", "").split("@")[0].replace(".", " ").title()
                if emp.get("manager_email")
                else "",
                "supervisorId": str(random.randint(7000, 7999)),
                "workEmail": emp["email"],
            }
        )
    return result


def _employees_as_gusto(employees: list[dict]) -> list[dict]:
    """Convert RICH_DATA employees to Gusto payroll format."""
    result = []
    for emp in employees:
        result.append(
            {
                "uuid": emp["employee_id"],
                "first_name": emp["first_name"],
                "last_name": emp["last_name"],
                "email": emp["email"],
                "department": emp["department"],
                "current_employment_status": (
                    "active" if emp["status"] == "active" else "terminated"
                ),
                "hire_date": emp["start_date"],
                "termination_date": emp.get("termination_date"),
                "is_contractor": emp.get("is_contractor", False),
                "onboarded": emp["status"] == "active",
            }
        )
    return result


def _employees_as_rippling(employees: list[dict]) -> list[dict]:
    """Convert RICH_DATA employees to Rippling format."""
    result = []
    for emp in employees:
        result.append(
            {
                "id": emp["employee_id"],
                "personalEmail": f"{emp['first_name'].lower()}.{emp['last_name'].lower()}@gmail.com",
                "workEmail": emp["email"],
                "displayName": f"{emp['first_name']} {emp['last_name']}",
                "department": emp["department"],
                "title": emp["title"],
                "employmentStatus": emp["status"],
                "startDate": emp["start_date"],
                "endDate": emp.get("termination_date"),
                "isActive": emp["status"] == "active",
                "manager": {"displayName": emp.get("manager_email", "")},
            }
        )
    return result


def _training_as_knowbe4(records: list[dict]) -> list[dict]:
    """Convert RICH_DATA training_records to KnowBe4 enrollment format."""
    result = []
    for tr in records:
        status = tr["status"]
        if status == "overdue":
            status = "not_started"
        result.append(
            {
                "enrollment_id": tr["record_id"],
                "user_name": tr["employee_email"].split("@")[0].replace(".", " ").title(),
                "user": {"name": tr["employee_email"].split("@")[0].replace(".", " ").title()},
                "module_name": tr["course_name"],
                "status": status,
                "due_date": tr["assigned_at"],
                **({"completion_date": tr["completed_at"]} if tr.get("completed_at") else {}),
            }
        )
    return result


def _code_findings_as_snyk(findings: list[dict]) -> list[dict]:
    """Convert RICH_DATA code_findings to Snyk issues format."""
    result = []
    for f in findings:
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        result.append(
            {
                "id": f["finding_id"],
                "attributes": {
                    "title": f["title"],
                    "effective_severity_level": sev_map.get(f["severity"], "medium"),
                    "problems": [{"id": f"CVE-2024-{random.randint(1000, 9999)}", "source": "CVE"}],
                    "cvss_score": {"critical": 9.1, "high": 7.5, "medium": 5.5, "low": 2.5}.get(
                        f["severity"], 5.5
                    ),
                    "package_name": f.get("rule_id", "unknown-pkg"),
                    "package_version": "1.0.0",
                    "is_fixable": f["status"] != "ignored",
                    "fix_versions": ["2.0.0"] if f["status"] != "ignored" else [],
                    "exploit_maturity": "proof-of-concept"
                    if f["severity"] == "critical"
                    else "no-known-exploit",
                    "language": f.get("language", "javascript"),
                    "coordinates": [{"project_name": f.get("repository", "acme/unknown")}],
                },
            }
        )
    return result


def _code_findings_as_github_dependabot(findings: list[dict]) -> list[dict]:
    """Convert RICH_DATA code_findings to GitHub Dependabot alert format."""
    result = []
    for f in findings:
        result.append(
            {
                "number": random.randint(1, 999),
                "repository": {"full_name": f.get("repository", "acme/unknown")},
                "security_advisory": {
                    "severity": f["severity"],
                    "cve_id": f"CVE-2024-{random.randint(1000, 9999)}",
                    "summary": f["title"],
                    "ghsa_id": f"GHSA-{''.join(random.choices('abcdefghijklmnop', k=9))}",
                    "cvss": {
                        "score": {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 2.5}.get(
                            f["severity"], 5.5
                        )
                    },
                },
                "dependency": {
                    "package": {
                        "name": f.get("rule_id", "unknown-pkg"),
                        "ecosystem": {
                            "python": "pip",
                            "javascript": "npm",
                            "typescript": "npm",
                            "go": "gomod",
                            "java": "maven",
                            "rust": "cargo",
                        }.get(f.get("language", ""), "npm"),
                    },
                    "manifest_path": f.get("file_path", "package.json"),
                },
            }
        )
    return result


def _code_findings_as_checkmarx(findings: list[dict]) -> list[dict]:
    """Convert RICH_DATA code_findings to Checkmarx SAST format."""
    result = []
    for f in findings:
        result.append(
            {
                "id": f["finding_id"],
                "queryName": f["title"],
                "severity": f["severity"].capitalize(),
                "status": "New" if f["status"] == "open" else "Resolved",
                "state": 0,
                "resultDeepLink": f"https://checkmarx.acme.com/results/{f['finding_id']}",
                "sourceFile": f.get("file_path", "unknown"),
                "sourceLine": f.get("line_number", 0),
                "destFile": f.get("file_path", "unknown"),
                "language": f.get("language", ""),
                "cweId": random.choice([79, 89, 200, 312, 502, 611, 798]),
            }
        )
    return result


def _code_findings_as_sonarqube(findings: list[dict]) -> list[dict]:
    """Convert RICH_DATA code_findings to SonarQube issues format."""
    result = []
    sev_map = {"critical": "CRITICAL", "high": "MAJOR", "medium": "MINOR", "low": "INFO"}
    for f in findings:
        result.append(
            {
                "key": f["finding_id"],
                "rule": f["rule_id"],
                "severity": sev_map.get(f["severity"], "MINOR"),
                "component": f"acme-app:{f.get('file_path', 'src/unknown')}",
                "message": f["title"],
                "status": "OPEN" if f["status"] == "open" else "RESOLVED",
                "type": random.choice(["BUG", "VULNERABILITY", "CODE_SMELL"]),
                "line": f.get("line_number", 0),
                "effort": f"{random.randint(5, 60)}min",
                "creationDate": f.get("detected_at", NOW.isoformat()),
            }
        )
    return result


def _code_findings_as_semgrep(findings: list[dict]) -> list[dict]:
    """Convert RICH_DATA code_findings to Semgrep format."""
    result = []
    for f in findings:
        result.append(
            {
                "id": f["finding_id"],
                "check_id": f["rule_id"],
                "path": f.get("file_path", "src/unknown"),
                "line": f.get("line_number", 0),
                "message": f["title"],
                "severity": f["severity"].upper(),
                "metadata": {
                    "category": f.get("category", "security"),
                    "cwe": [f"CWE-{random.choice([79, 89, 200, 312, 502])}"],
                    "owasp": [random.choice(["A01:2021", "A02:2021", "A03:2021"])],
                },
                "fix": f"// Fix: {f['title']}",
            }
        )
    return result


def _code_findings_as_veracode(findings: list[dict]) -> list[dict]:
    """Convert RICH_DATA code_findings to Veracode format."""
    result = []
    for f in findings:
        result.append(
            {
                "issue_id": int(f["finding_id"].replace("sast-", "").replace("-", "")[:8], 16)
                % 100000,
                "finding_category": {"name": f.get("category", "security")},
                "severity": {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(f["severity"], 3),
                "cwe": {"id": random.choice([79, 89, 200, 312, 502, 611, 798])},
                "display_text": f["title"],
                "files": {
                    "source_file": {
                        "file": f.get("file_path", "unknown"),
                        "line": f.get("line_number", 0),
                    }
                },
                "finding_status": {"status": "OPEN" if f["status"] == "open" else "CLOSED"},
            }
        )
    return result


def _code_findings_as_gitguardian(findings: list[dict]) -> list[dict]:
    """Convert RICH_DATA code_findings to GitGuardian secret format."""
    result = []
    secret_types = [
        "AWS Access Key",
        "GitHub Token",
        "Slack Webhook URL",
        "Generic Password",
        "RSA Private Key",
        "JWT Secret",
    ]
    for f in findings:
        result.append(
            {
                "id": f["finding_id"],
                "type": random.choice(secret_types),
                "status": "triggered" if f["status"] == "open" else "resolved",
                "date": f.get("detected_at", NOW.isoformat()),
                "tags": ["leaked_secret"],
                "repository": f.get("repository", "acme/unknown"),
                "file_path": f.get("file_path", "unknown"),
                "line": f.get("line_number", 0),
                "validity": random.choice(["valid", "invalid", "unknown"]),
            }
        )
    return result


def _vulns_as_nessus(vulns: list[dict]) -> list[dict]:
    """Convert RICH_DATA vulnerabilities to Nessus scan results format."""
    sev_num = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    result = []
    for v in vulns:
        result.append(
            {
                "plugin_id": random.randint(10000, 99999),
                "plugin_name": v["title"],
                "severity": sev_num.get(v["severity"], 2),
                "host_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "host_fqdn": v["affected_resource"],
                "protocol": random.choice(["tcp", "udp"]),
                "port": random.choice([22, 80, 443, 8080, 3306, 5432]),
                "cve": v["cve_id"],
                "cvss_base_score": v["cvss_score"],
                "solution": f"Upgrade {v['package_name']} to {v['fixed_version']}",
                "risk_factor": v["severity"].capitalize(),
                "first_discovered": v["first_seen"],
                "last_observed": v["last_seen"],
            }
        )
    return result


def _vulns_as_trivy(vulns: list[dict]) -> list[dict]:
    """Convert RICH_DATA vulnerabilities to Trivy scan format."""
    result = []
    for v in vulns:
        result.append(
            {
                "VulnerabilityID": v["cve_id"],
                "PkgName": v["package_name"],
                "InstalledVersion": v["installed_version"],
                "FixedVersion": v["fixed_version"],
                "Severity": v["severity"].upper(),
                "Title": v["title"],
                "Description": v.get("description", v["title"]),
                "CVSS": {"nvd": {"V3Score": v["cvss_score"]}},
                "References": [f"https://nvd.nist.gov/vuln/detail/{v['cve_id']}"],
                "Target": v["affected_resource"],
            }
        )
    return result


def _email_as_proofpoint(emails: list[dict]) -> dict:
    """Split RICH_DATA email_events into Proofpoint-style blocked/delivered."""
    blocked = []
    delivered_threats = []
    for e in emails:
        if e["status"] in ("blocked", "quarantined"):
            blocked.append({"subject": e["subject"]})
        if e.get("threat_type"):
            delivered_threats.append(
                {
                    "GUID": e["message_id"],
                    "subject": e["subject"],
                    "sender": e["from_address"],
                    "recipient": e["to_address"],
                    "threatsInfoMap": {
                        "url" if e["threat_type"] == "phishing" else "attachment": {
                            "threatScore": random.randint(60, 99)
                            if e["threat_type"] == "phishing"
                            else random.randint(30, 70),
                            "classification": e["threat_type"],
                        },
                    },
                }
            )
    return {"blocked": blocked, "delivered_threats": delivered_threats}


def _email_as_abnormal(emails: list[dict]) -> list[dict]:
    """Convert RICH_DATA email_events to Abnormal Security threat format."""
    result = []
    for e in emails:
        if not e.get("threat_type"):
            continue
        result.append(
            {
                "threatId": e["message_id"],
                "abxMessageId": random.randint(100000, 999999),
                "subject": e["subject"],
                "fromAddress": e["from_address"],
                "toAddress": e["to_address"],
                "attackType": e["threat_type"].upper(),
                "attackStrategy": random.choice(
                    [
                        "Credential Phishing",
                        "BEC",
                        "Malware Delivery",
                        "Social Engineering",
                    ]
                )
                if e["threat_type"] == "phishing"
                else "Spam",
                "sentTime": e["timestamp"],
                "remediationStatus": "Auto-Remediated"
                if e["status"] != "delivered"
                else "No Action",
            }
        )
    return result


def _dns_as_purview(queries: list[dict]) -> list[dict]:
    """Convert RICH_DATA dns_queries to Purview DLP alert format."""
    result = []
    for q in queries:
        if q["action"] != "block":
            continue
        result.append(
            {
                "alert_id": q["query_id"],
                "policy_name": f"DLP-{q.get('threat_type', 'policy')}",
                "severity": "High" if q.get("threat_type") else "Medium",
                "user": q.get("user_email", ""),
                "matched_content": q["domain"],
                "action_taken": "Block",
                "created_at": q["timestamp"],
            }
        )
    return result


def _dns_as_zscaler(queries: list[dict]) -> list[dict]:
    """Convert RICH_DATA dns_queries to Zscaler web transaction format."""
    result = []
    for q in queries:
        result.append(
            {
                "url": f"https://{q['domain']}/",
                "user": q.get("user_email", ""),
                "action": q["action"].upper(),
                "urlCategory": q["category"],
                "threatName": q.get("threat_type", ""),
                "clientIP": q["source_ip"],
                "timestamp": q["timestamp"],
            }
        )
    return result


def _dns_as_netskope(queries: list[dict]) -> list[dict]:
    """Convert RICH_DATA dns_queries to Netskope CASB alert format."""
    result = []
    for q in queries:
        result.append(
            {
                "alert_id": q["query_id"],
                "alert_name": f"Web activity: {q['domain']}",
                "user": q.get("user_email", ""),
                "app": q["domain"],
                "category": q["category"],
                "action": q["action"],
                "risk_level": "high" if q.get("threat_type") else "low",
                "timestamp": q["timestamp"],
                "src_ip": q["source_ip"],
            }
        )
    return result


def _vendors_as_securityscorecard(vendors: list[dict]) -> list[dict]:
    """Convert RICH_DATA vendor_assessments to SecurityScorecard format."""
    result = []
    for v in vendors:
        result.append(
            {
                "domain": f"{v['vendor_name'].lower().replace(' ', '-')}.com",
                "name": v["vendor_name"],
                "score": v["risk_score"],
                "grade": v["rating"],
                "industry": v["category"],
                "last_score_change": v["last_assessed"],
                "size": random.choice(["small", "medium", "large"]),
            }
        )
    return result


def _vendors_as_bitsight(vendors: list[dict]) -> list[dict]:
    """Convert RICH_DATA vendor_assessments to BitSight format."""
    result = []
    for v in vendors:
        result.append(
            {
                "guid": v["vendor_id"],
                "name": v["vendor_name"],
                "rating": min(900, v["risk_score"] * 10),
                "rating_date": v["last_assessed"],
                "industry": v["category"],
                "country": "US",
                "percentile": v["risk_score"],
            }
        )
    return result


def _policies_as_confluence(policies: list[dict]) -> list[dict]:
    """Convert RICH_DATA policy_documents to Confluence page format."""
    result = []
    for p in policies:
        result.append(
            {
                "id": p["policy_id"],
                "title": p["title"],
                "status": "current" if p["status"] == "active" else "draft",
                "version": {"number": int(p["version"].split(".")[0])},
                "_links": {"webui": f"/wiki/spaces/SEC/pages/{p['policy_id']}"},
                "history": {
                    "lastUpdated": {
                        "when": p["last_reviewed"],
                        "by": {
                            "displayName": p["owner_email"].split("@")[0].replace(".", " ").title()
                        },
                    },
                },
                "_metadata": {
                    "labels": {"results": [{"name": p["category"]}]},
                },
            }
        )
    return result


def _policies_as_onetrust(policies: list[dict]) -> list[dict]:
    """Convert RICH_DATA policy_documents to OneTrust assessment format."""
    result = []
    for p in policies:
        result.append(
            {
                "id": p["policy_id"],
                "name": p["title"],
                "assessmentType": "PIA" if "privacy" in p["category"].lower() else "DPIA",
                "status": "APPROVED" if p["status"] == "active" else "IN_REVIEW",
                "riskLevel": random.choice(["LOW", "MEDIUM", "HIGH"]),
                "lastUpdated": p["last_reviewed"],
                "reviewer": p["owner_email"],
            }
        )
    return result


def _policies_as_servicenow(policies: list[dict]) -> list[dict]:
    """Convert RICH_DATA policy_documents to ServiceNow GRC policy format."""
    result = []
    for p in policies:
        result.append(
            {
                "sys_id": p["policy_id"],
                "name": p["title"],
                "state": "published" if p["status"] == "active" else "draft",
                "category": p["category"],
                "owner": p["owner_email"],
                "last_reviewed": p["last_reviewed"],
                "review_date": p.get("review_due", ""),
                "version": p["version"],
            }
        )
    return result


def _instances_filter_cloud(instances: list[dict], cloud: str) -> list[dict]:
    """Filter RICH_DATA cloud_instances by cloud provider."""
    return [i for i in instances if i["cloud"] == cloud]


def _sg_filter_cloud(sgs: list[dict], cloud: str) -> list[dict]:
    """Filter RICH_DATA security_groups by cloud provider."""
    return [sg for sg in sgs if sg["cloud"] == cloud]


def _buckets_filter_cloud(buckets: list[dict], cloud: str) -> list[dict]:
    """Filter RICH_DATA storage_buckets by cloud provider."""
    return [b for b in buckets if b["cloud"] == cloud]


def _iam_filter_cloud(policies: list[dict], cloud: str) -> list[dict]:
    """Filter RICH_DATA iam_policies by cloud provider."""
    return [p for p in policies if p["cloud"] == cloud]


# ---------------------------------------------------------------------------
# Mock connectors
# ---------------------------------------------------------------------------


__all__ = [
    "NOW",
    "RICH_DATA",
    "_RICH_DATA_LOCK",
    "_RICH_DATA_READY",
    "_alerts_as_elastic",
    "_alerts_as_sentinel",
    "_alerts_as_splunk",
    "_auth_logs_as_okta",
    "_buckets_filter_cloud",
    "_code_findings_as_checkmarx",
    "_code_findings_as_gitguardian",
    "_code_findings_as_github_dependabot",
    "_code_findings_as_semgrep",
    "_code_findings_as_snyk",
    "_code_findings_as_sonarqube",
    "_code_findings_as_veracode",
    "_devices_as_intune",
    "_devices_as_jamf",
    "_devices_as_kandji",
    "_dns_as_netskope",
    "_dns_as_purview",
    "_dns_as_zscaler",
    "_email_as_abnormal",
    "_email_as_proofpoint",
    "_employees_as_bamboohr",
    "_employees_as_gusto",
    "_employees_as_rippling",
    "_employees_as_workday",
    "_endpoints_as_crowdstrike",
    "_endpoints_as_defender",
    "_endpoints_as_sentinelone",
    "_endpoints_as_sophos",
    "_ensure_rich_data",
    "_iam_filter_cloud",
    "_instances_filter_cloud",
    "_policies_as_confluence",
    "_policies_as_onetrust",
    "_policies_as_servicenow",
    "_sg_filter_cloud",
    "_training_as_knowbe4",
    "_users_as_cyberark",
    "_users_as_entra",
    "_users_as_okta",
    "_users_as_sailpoint",
    "_vendors_as_bitsight",
    "_vendors_as_securityscorecard",
    "_vulns_as_crowdstrike",
    "_vulns_as_nessus",
    "_vulns_as_qualys",
    "_vulns_as_tenable",
    "_vulns_as_trivy",
    "_vulns_as_wiz",
]
