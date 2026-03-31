#!/usr/bin/env python3
"""Generate warlock/frameworks/remediation/nist_800_53.yaml with all 1,176 controls."""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Load control IDs from the framework YAML
with open(ROOT / "warlock" / "frameworks" / "nist_800_53.yaml") as f:
    fw = yaml.safe_load(f)

all_controls = []
for fam, fam_data in fw["control_families"].items():
    for ctrl_id in fam_data.get("controls", {}):
        all_controls.append(ctrl_id)

print(f"Total controls to generate: {len(all_controls)}")

# ── Assertion mappings from assertions.py ──
ASSERTION_MAP = {
    "AC-2": "mfa_enabled,no_root_access_keys",
    "AC-6": "no_root_access_keys,privileged_access_managed",
    "AC-17": "no_open_security_groups",
    "AT-2": "training_completion_rate,phishing_failure_rate",
    "AT-3": "training_completion_rate,phishing_failure_rate",
    "AU-2": "cloudtrail_enabled",
    "AU-12": "cloudtrail_enabled",
    "CA-7": "config_recorder_enabled",
    "CM-2": "config_recorder_enabled",
    "CM-3": "change_request_approved",
    "CM-4": "change_request_approved",
    "CM-6": "config_recorder_enabled",
    "CP-9": "backup_job_successful",
    "CP-10": "backup_job_successful",
    "IA-2": "mfa_enabled",
    "IA-5": "password_policy_compliant",
    "IR-5": "siem_monitoring_active",
    "PS-3": "background_check_completed",
    "PS-4": "access_reviews_current",
    "PS-6": "employment_agreement_signed",
    "PS-7": "employment_agreement_signed",
    "RA-5": "vulnerability_scan_current",
    "SA-11": "no_critical_code_vulns",
    "SC-7": "no_open_security_groups,dlp_policies_active",
    "SC-28": "encryption_at_rest",
    "SI-2": "vulnerability_scan_current",
    "SI-3": "endpoint_protection_active",
    "SI-4": "guardduty_enabled",
    "SI-5": "securityhub_enabled",
}

# ── Control metadata: summary, remediation_steps, console_path, evidence_types, recommended_reading ──
# This is the full NIST 800-53 Rev 5 knowledge base.


def family_of(ctrl_id):
    return ctrl_id.split("-")[0]


def base_control(ctrl_id):
    if "(" in ctrl_id:
        return ctrl_id.split("(")[0]
    return ctrl_id


def enhancement_num(ctrl_id):
    if "(" in ctrl_id:
        return ctrl_id.split("(")[1].rstrip(")")
    return None


# ── FULL CONTROL DEFINITIONS ──
# For each base control, we define summary, steps, console_path, evidence_types, reading.
# Enhancement controls get specific additions.

CONTROLS = {}

# ============================================================
# AC — Access Control
# ============================================================

CONTROLS["AC-1"] = {
    "summary": "Develop, document, and disseminate access control policy and procedures",
    "remediation_steps": [
        "Draft an access control policy covering all system access requirements",
        "Define roles and responsibilities for access control administration",
        "Establish review cycle (at least annually)",
        "Distribute policy to all organizational personnel",
    ],
    "console_path": "Confluence > SEC Space > Access Control Policy",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-1 Assessment Procedures",
        "NIST SP 800-53B: AC-1 Control Baselines",
    ],
    "evidence_types": ["policy_document", "policy_review_date"],
}

CONTROLS["AC-2"] = {
    "summary": "Manage system accounts including creating, enabling, modifying, disabling, and removing accounts",
    "remediation_steps": [
        "Identify all system accounts and their authorized users",
        "Enable MFA for all interactive accounts",
        "Implement automated account provisioning and deprovisioning",
        "Review all accounts quarterly and remove inactive accounts",
        "Disable root/admin account access keys",
    ],
    "console_path": "IAM > Users > Security credentials",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2 Assessment Procedures",
        "CIS AWS Foundations Benchmark: 1.1-1.22",
    ],
    "evidence_types": ["iam_credential_report", "okta_users", "entra_users"],
}

CONTROLS["AC-2(1)"] = {
    "summary": "Automated system account management",
    "remediation_steps": [
        "Configure automated provisioning via SCIM/Okta lifecycle management",
        "Implement automated deprovisioning triggers on HR termination events",
        "Set up automated account status notifications",
        "Verify SCIM sync is active between IdP and all downstream applications",
    ],
    "console_path": "Okta > Directory > Profile Sources > SCIM Provisioning",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(1) Assessment Procedures",
        "SCIM Protocol RFC 7644",
    ],
    "evidence_types": ["okta_users", "entra_users", "sailpoint_identities"],
}

CONTROLS["AC-2(2)"] = {
    "summary": "Automated temporary and emergency account management",
    "remediation_steps": [
        "Configure automatic expiration for temporary accounts",
        "Set maximum lifetime for emergency accounts (72 hours recommended)",
        "Enable alerts when temporary accounts exceed their authorized period",
        "Document emergency account creation and removal procedures",
    ],
    "console_path": "Okta > Directory > People > Account Expiration Settings",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(2) Assessment Procedures",
    ],
    "evidence_types": ["okta_users", "entra_users", "iam_credential_report"],
}

CONTROLS["AC-2(3)"] = {
    "summary": "Disable accounts after period of inactivity",
    "remediation_steps": [
        "Configure automatic disabling of accounts after 90 days of inactivity",
        "Set up IAM Access Analyzer to identify unused credentials",
        "Enable Okta inactive user detection and automatic suspension",
        "Generate monthly reports of inactive accounts for review",
    ],
    "console_path": "IAM > Access Analyzer > Findings | Okta > Reports > Inactive Users",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(3) Assessment Procedures",
        "CIS AWS Foundations Benchmark: 1.12",
    ],
    "evidence_types": ["iam_credential_report", "okta_users", "entra_users"],
}

CONTROLS["AC-2(4)"] = {
    "summary": "Automated audit actions for account management",
    "remediation_steps": [
        "Enable CloudTrail logging for all IAM events",
        "Configure Okta System Log forwarding to SIEM",
        "Set up alerts for account creation, modification, and deletion events",
        "Ensure audit logs capture account enable/disable actions",
    ],
    "console_path": "CloudTrail > Event History > IAM | Okta > Reports > System Log",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(4) Assessment Procedures",
    ],
    "evidence_types": ["cloudtrail_trails", "okta_system_log", "entra_directory_audits"],
}

CONTROLS["AC-2(5)"] = {
    "summary": "Inactivity logout for user sessions",
    "remediation_steps": [
        "Configure session timeout to 15 minutes of inactivity",
        "Set Okta global session policy idle timeout",
        "Configure Entra ID conditional access session controls",
        "Verify application-level session timeouts are enforced",
    ],
    "console_path": "Okta > Security > Global Session Policy > Idle Timeout",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(5) Assessment Procedures",
    ],
    "evidence_types": ["okta_policies", "entra_conditional_access_policies"],
}

CONTROLS["AC-2(6)"] = {
    "summary": "Dynamic privilege management",
    "remediation_steps": [
        "Implement just-in-time privileged access via CyberArk or Azure PIM",
        "Configure automatic privilege elevation with time-bound sessions",
        "Set up approval workflows for privilege escalation requests",
        "Enable audit logging for all privilege changes",
    ],
    "console_path": "CyberArk > Policies > JIT Access | Azure PIM > Roles",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(6) Assessment Procedures",
    ],
    "evidence_types": ["cyberark_accounts", "cyberark_safes", "sailpoint_roles"],
}

CONTROLS["AC-2(7)"] = {
    "summary": "Privileged user accounts with role-based schemes",
    "remediation_steps": [
        "Define privileged roles using RBAC with least privilege",
        "Require separate accounts for privileged and non-privileged access",
        "Monitor privileged account usage and alert on anomalies",
        "Review privileged role assignments quarterly",
    ],
    "console_path": "IAM > Roles > Administrator roles | CyberArk > Accounts",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(7) Assessment Procedures",
    ],
    "evidence_types": ["iam_credential_report", "cyberark_accounts"],
}

CONTROLS["AC-2(8)"] = {
    "summary": "Dynamic account management based on atypical usage",
    "remediation_steps": [
        "Enable GuardDuty or Entra Identity Protection for anomaly detection",
        "Configure risk-based conditional access policies",
        "Set up automated account lockout on suspicious activity",
        "Review anomaly detection alerts weekly",
    ],
    "console_path": "GuardDuty > Findings | Entra ID > Identity Protection",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(8) Assessment Procedures",
    ],
    "evidence_types": ["entra_risky_users", "entra_sign_ins"],
}

CONTROLS["AC-2(9)"] = {
    "summary": "Restrictions on use of shared and group accounts",
    "remediation_steps": [
        "Inventory all shared and group accounts across systems",
        "Require individual accountability for shared account usage",
        "Implement shared account check-out/check-in via PAM tool",
        "Document business justification for each shared account",
    ],
    "console_path": "CyberArk > Safes > Shared Accounts",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(9) Assessment Procedures",
    ],
    "evidence_types": ["cyberark_accounts", "iam_users"],
}

CONTROLS["AC-2(10)"] = {
    "summary": "Shared and group account credential change on membership change",
    "remediation_steps": [
        "Configure automatic credential rotation when group membership changes",
        "Implement PAM-managed credential rotation for shared accounts",
        "Set up alerts for group membership changes on privileged accounts",
        "Document credential change procedures for shared accounts",
    ],
    "console_path": "CyberArk > Policies > Credential Rotation",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(10) Assessment Procedures",
    ],
    "evidence_types": ["cyberark_accounts"],
}

CONTROLS["AC-2(11)"] = {
    "summary": "Usage conditions for system accounts",
    "remediation_steps": [
        "Define usage conditions and restrictions for each account type",
        "Implement conditional access policies enforcing usage conditions",
        "Configure time-of-day and location-based access restrictions",
        "Monitor and alert on usage condition violations",
    ],
    "console_path": "Entra ID > Conditional Access > Policies",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(11) Assessment Procedures",
    ],
    "evidence_types": ["entra_conditional_access_policies", "okta_policies"],
}

CONTROLS["AC-2(12)"] = {
    "summary": "Account monitoring for atypical usage",
    "remediation_steps": [
        "Enable user and entity behavior analytics (UEBA)",
        "Configure GuardDuty or Sentinel for atypical login detection",
        "Set up alerts for impossible travel, unusual hours, and privilege escalation",
        "Review atypical usage reports weekly",
    ],
    "console_path": "Sentinel > UEBA | GuardDuty > Findings",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(12) Assessment Procedures",
    ],
    "evidence_types": ["entra_risky_users", "entra_sign_ins", "okta_system_log"],
}

CONTROLS["AC-2(13)"] = {
    "summary": "Disable accounts for high-risk individuals",
    "remediation_steps": [
        "Define criteria for high-risk individual designation",
        "Implement automated account disabling upon risk threshold breach",
        "Configure integration between threat intelligence and IAM",
        "Document escalation procedures for high-risk account actions",
    ],
    "console_path": "Entra ID > Identity Protection > Risky Users",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-2(13) Assessment Procedures",
    ],
    "evidence_types": ["entra_risky_users"],
}

CONTROLS["AC-3"] = {
    "summary": "Enforce approved authorizations for logical access to information and system resources",
    "remediation_steps": [
        "Implement role-based access control (RBAC) across all systems",
        "Configure IAM policies with least privilege principles",
        "Enable conditional access policies in identity provider",
        "Review and validate access control lists quarterly",
    ],
    "console_path": "IAM > Policies | Okta > Applications > Access Policies",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-3 Assessment Procedures",
        "NIST SP 800-162: ABAC Guide",
    ],
    "evidence_types": ["iam_users", "okta_policies", "entra_conditional_access_policies"],
}

CONTROLS["AC-3(1)"] = {
    "summary": "Restricted access to privileged functions",
    "remediation_steps": [
        "Identify and document all privileged functions",
        "Restrict privileged function access to authorized roles only",
        "Implement break-glass procedures for emergency privileged access",
        "Audit privileged function usage monthly",
    ],
    "console_path": "IAM > Policies > AdministratorAccess",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(1) Assessment Procedures"],
    "evidence_types": ["iam_users", "iam_policies"],
}

CONTROLS["AC-3(2)"] = {
    "summary": "Dual authorization for access",
    "remediation_steps": [
        "Implement dual-approval workflows for sensitive operations",
        "Configure approval chains in PAM tool for critical systems",
        "Document which operations require dual authorization",
        "Test dual authorization controls quarterly",
    ],
    "console_path": "CyberArk > Policies > Dual Control",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(2) Assessment Procedures"],
    "evidence_types": ["cyberark_accounts"],
}

CONTROLS["AC-3(3)"] = {
    "summary": "Mandatory access control enforcement",
    "remediation_steps": [
        "Implement mandatory access control (MAC) labels on classified data",
        "Configure SELinux or AppArmor policies on Linux systems",
        "Enforce data classification labels in DLP policies",
        "Verify MAC enforcement cannot be overridden by users",
    ],
    "console_path": "Security Center > Data Classification > Labels",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(3) Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AC-3(4)"] = {
    "summary": "Discretionary access control enforcement",
    "remediation_steps": [
        "Implement DAC with identity-based access control lists",
        "Configure file system permissions using principle of least privilege",
        "Enable object owner-managed sharing controls",
        "Audit discretionary access grants quarterly",
    ],
    "console_path": "S3 > Bucket Policy | Azure Storage > Access Control",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(4) Assessment Procedures"],
    "evidence_types": ["s3_buckets", "storage_accounts"],
}

CONTROLS["AC-3(5)"] = {
    "summary": "Security-relevant information access restrictions",
    "remediation_steps": [
        "Restrict access to audit logs, security configurations, and vulnerability data",
        "Implement separate roles for security administration",
        "Configure read-only access for audit and compliance teams",
        "Alert on unauthorized access attempts to security-relevant data",
    ],
    "console_path": "IAM > Policies > SecurityAudit role",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(5) Assessment Procedures"],
    "evidence_types": ["iam_policies"],
}

CONTROLS["AC-3(6)"] = {
    "summary": "Protection of user and system information",
    "remediation_steps": [
        "Encrypt sensitive user data at rest and in transit",
        "Implement data masking for PII in non-production environments",
        "Configure access controls on databases containing sensitive information",
        "Enable audit logging on all access to protected information",
    ],
    "console_path": "RDS > Encryption | DynamoDB > Encryption",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(6) Assessment Procedures"],
    "evidence_types": ["config_snapshots", "encryption_status"],
}

CONTROLS["AC-3(7)"] = {
    "summary": "Role-based access control",
    "remediation_steps": [
        "Define organizational roles and their access requirements",
        "Implement RBAC across all systems and applications",
        "Map roles to least-privilege permission sets",
        "Review role definitions and assignments semi-annually",
    ],
    "console_path": "IAM > Roles | Okta > Directory > Groups",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(7) Assessment Procedures"],
    "evidence_types": ["iam_users", "okta_groups"],
}

CONTROLS["AC-3(8)"] = {
    "summary": "Revocation of access authorizations",
    "remediation_steps": [
        "Implement immediate access revocation capability",
        "Configure automated deprovisioning on termination events",
        "Test access revocation procedures quarterly",
        "Verify revocation propagates to all connected systems",
    ],
    "console_path": "Okta > Lifecycle Management > Deprovisioning",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(8) Assessment Procedures"],
    "evidence_types": ["okta_users", "entra_users"],
}

CONTROLS["AC-3(9)"] = {
    "summary": "Controlled release of information",
    "remediation_steps": [
        "Implement data loss prevention (DLP) policies",
        "Configure information release approval workflows",
        "Enable content inspection on outbound communications",
        "Monitor and log all information release activities",
    ],
    "console_path": "Microsoft Purview > DLP Policies",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(9) Assessment Procedures"],
    "evidence_types": ["dlp_policies"],
}

CONTROLS["AC-3(10)"] = {
    "summary": "Audited override of access control mechanisms",
    "remediation_steps": [
        "Define conditions under which access overrides are permitted",
        "Implement audited break-glass procedures",
        "Configure alerts for all access control overrides",
        "Review override audit logs weekly",
    ],
    "console_path": "CyberArk > Break Glass > Audit Log",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(10) Assessment Procedures"],
    "evidence_types": ["audit_logs"],
}

CONTROLS["AC-3(11)"] = {
    "summary": "Restrict access to specific information types",
    "remediation_steps": [
        "Classify information types requiring restricted access",
        "Implement attribute-based access control (ABAC) for sensitive data types",
        "Configure DLP policies aligned to information classification",
        "Audit access to restricted information types monthly",
    ],
    "console_path": "Microsoft Purview > Sensitivity Labels",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(11) Assessment Procedures"],
    "evidence_types": ["dlp_policies", "config_snapshots"],
}

CONTROLS["AC-3(12)"] = {
    "summary": "Assert and enforce application access",
    "remediation_steps": [
        "Implement application-level authorization checks",
        "Configure API gateway policies to enforce access control",
        "Use OAuth 2.0 scopes to limit application access",
        "Verify application access controls in security testing",
    ],
    "console_path": "API Gateway > Authorizers | Okta > Applications > Policies",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(12) Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AC-3(13)"] = {
    "summary": "Attribute-based access control",
    "remediation_steps": [
        "Define access control attributes (role, department, clearance, location)",
        "Implement ABAC policies in authorization engine",
        "Configure attribute sources and validation",
        "Test ABAC policy evaluation with representative scenarios",
    ],
    "console_path": "IAM > Access Analyzer | OPA > Policies",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-3(13) Assessment Procedures",
        "NIST SP 800-162: Guide to ABAC",
    ],
    "evidence_types": ["config_snapshots", "iam_policies"],
}

CONTROLS["AC-3(14)"] = {
    "summary": "Individual access to data",
    "remediation_steps": [
        "Implement mechanisms for individuals to access their own data",
        "Configure privacy access request portals",
        "Enable audit logging of individual data access requests",
        "Verify data access rights align with privacy regulations",
    ],
    "console_path": "Privacy Portal > Data Subject Requests",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(14) Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AC-3(15)"] = {
    "summary": "Discretionary and mandatory access control",
    "remediation_steps": [
        "Implement both DAC and MAC where required by data classification",
        "Configure hybrid access control enforcement",
        "Document which data requires MAC vs DAC controls",
        "Verify MAC cannot be overridden by DAC permissions",
    ],
    "console_path": "Security Center > Access Control Configuration",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-3(15) Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AC-4"] = {
    "summary": "Enforce approved authorizations for controlling the flow of information within the system and between systems",
    "remediation_steps": [
        "Configure network security groups and firewall rules for flow control",
        "Implement data flow diagrams and enforce approved paths",
        "Enable VPC flow logs to monitor information flows",
        "Review and update flow control policies quarterly",
    ],
    "console_path": "VPC > Security Groups | Azure NSG > Rules | GCP Firewall",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-4 Assessment Procedures",
    ],
    "evidence_types": ["ec2_security_groups", "network_security_groups", "compute_firewall_rules"],
}

# AC-4 enhancements
for enh, summ, steps, cp in [
    (
        "1",
        "Object security and privacy attributes",
        [
            "Tag data objects with security and privacy classification attributes",
            "Enforce flow control based on object attributes",
            "Implement metadata-driven routing policies",
            "Verify attribute inheritance on data transformation",
        ],
        "Microsoft Purview > Sensitivity Labels",
    ),
    (
        "2",
        "Processing domains for information flow",
        [
            "Define processing domains with distinct security requirements",
            "Implement network segmentation between processing domains",
            "Configure cross-domain solutions for authorized flows",
            "Monitor and log all cross-domain information transfers",
        ],
        "VPC > Subnets > Route Tables",
    ),
    (
        "3",
        "Dynamic information flow control",
        [
            "Implement dynamic flow control based on real-time risk assessment",
            "Configure adaptive network policies responding to threat intelligence",
            "Enable automated flow restriction on detected anomalies",
            "Test dynamic flow control with simulated threat scenarios",
        ],
        "Security Hub > Automation Rules",
    ),
    (
        "4",
        "Flow control of encrypted information",
        [
            "Implement TLS inspection for encrypted traffic flows",
            "Configure flow control policies that operate on encrypted data attributes",
            "Deploy decryption gateways at trust boundaries",
            "Document exceptions for end-to-end encrypted flows",
        ],
        "WAF > TLS Inspection | Firewall > Decryption Policies",
    ),
    (
        "5",
        "Embedded data types",
        [
            "Implement deep content inspection for embedded data types",
            "Configure DLP to detect sensitive data in nested file formats",
            "Block unauthorized embedded content types at email gateways",
            "Enable content disarm and reconstruction (CDR) for file uploads",
        ],
        "Microsoft Purview > DLP > Content Inspection",
    ),
    (
        "6",
        "Metadata",
        [
            "Define metadata flow control policies",
            "Implement metadata stripping at trust boundaries",
            "Configure metadata validation for incoming data flows",
            "Monitor metadata integrity across system boundaries",
        ],
        "API Gateway > Request Transformation",
    ),
    (
        "7",
        "One-way flow mechanisms",
        [
            "Deploy data diodes for one-way information flow",
            "Configure unidirectional security gateways",
            "Verify one-way flow cannot be reversed through protocol exploitation",
            "Test one-way flow mechanisms annually",
        ],
        "Network > Data Diode Configuration",
    ),
    (
        "8",
        "Security and privacy policy filters",
        [
            "Implement content filters at network boundaries",
            "Configure policy-based routing with DLP inspection",
            "Enable email content filtering for sensitive data",
            "Test filter effectiveness with policy compliance scenarios",
        ],
        "Email Security > Content Filters | WAF > Rules",
    ),
    (
        "9",
        "Human reviews for flow control",
        [
            "Define information types requiring manual review before release",
            "Implement approval workflows for sensitive data transfers",
            "Configure hold-and-review queues for flagged content",
            "Document human review criteria and response time SLAs",
        ],
        "DLP > Incident Management > Review Queue",
    ),
    (
        "10",
        "Enable and disable security or privacy policy filters",
        [
            "Implement privileged controls for filter management",
            "Require dual authorization to disable policy filters",
            "Log all filter enable/disable actions",
            "Alert on any policy filter state changes",
        ],
        "Security Center > Policy Management",
    ),
    (
        "11",
        "Configuration of security or privacy policy filters",
        [
            "Restrict filter configuration to authorized administrators",
            "Implement change management for filter rule modifications",
            "Version control all filter configurations",
            "Test filter changes in staging before production deployment",
        ],
        "WAF > Rules > Configuration Management",
    ),
    (
        "12",
        "Data type identifiers",
        [
            "Implement data type identification and classification",
            "Configure automated data discovery and labeling",
            "Map data types to flow control policies",
            "Validate data type identification accuracy quarterly",
        ],
        "Microsoft Purview > Data Catalog",
    ),
    (
        "13",
        "Decomposition into policy-relevant subcomponents",
        [
            "Decompose complex data into policy-evaluable components",
            "Configure deep packet inspection for structured data",
            "Implement content-aware flow control",
            "Test decomposition accuracy with representative data samples",
        ],
        "DLP > Content Inspection > Advanced",
    ),
    (
        "14",
        "Security or privacy policy filter constraints",
        [
            "Define hard limits on filter processing to prevent bypass via resource exhaustion",
            "Configure timeouts and size limits on content inspection",
            "Implement fail-closed behavior when filters are overwhelmed",
            "Monitor filter performance and capacity",
        ],
        "WAF > Rate Limiting | DLP > Processing Limits",
    ),
    (
        "15",
        "Detection of unsanctioned information",
        [
            "Implement DLP scanning for unauthorized data exfiltration",
            "Configure CASB for shadow IT and unsanctioned cloud service detection",
            "Enable network monitoring for unauthorized data transfers",
            "Alert on detection of unsanctioned information flows",
        ],
        "CASB > Shadow IT | DLP > Alerts",
    ),
    (
        "16",
        "Information transfers on interconnected systems",
        [
            "Define approved interconnections and data exchange agreements",
            "Implement ISA/MOU for all system interconnections",
            "Configure monitoring for all interconnected system transfers",
            "Review interconnection agreements annually",
        ],
        "Network > Interconnection Security Agreements",
    ),
    (
        "17",
        "Domain authentication",
        [
            "Implement domain-level authentication for information transfers",
            "Configure mutual TLS between interconnected domains",
            "Verify domain identity before accepting data flows",
            "Monitor for domain spoofing in information transfers",
        ],
        "Certificate Manager > mTLS Certificates",
    ),
    (
        "18",
        "Security attribute binding",
        [
            "Bind security attributes to information at creation",
            "Implement cryptographic binding of attributes to data",
            "Verify attribute binding integrity during flow processing",
            "Prevent attribute modification during transit",
        ],
        "Data Classification > Attribute Binding",
    ),
    (
        "19",
        "Validation of metadata",
        [
            "Implement metadata schema validation at flow boundaries",
            "Configure automated metadata integrity checks",
            "Reject information flows with invalid or missing metadata",
            "Log metadata validation failures for investigation",
        ],
        "API Gateway > Schema Validation",
    ),
    (
        "20",
        "Approved solutions",
        [
            "Maintain approved list of information flow solutions",
            "Verify all flow control mechanisms are from approved solutions",
            "Evaluate new flow solutions against security requirements",
            "Decommission unapproved flow solutions",
        ],
        "CMDB > Approved Technologies",
    ),
    (
        "21",
        "Physical or logical separation of information flows",
        [
            "Implement physical or logical separation for different classification levels",
            "Configure VLANs or separate VPCs for classified information flows",
            "Verify separation effectiveness through penetration testing",
            "Document all information flow separation mechanisms",
        ],
        "VPC > Network Segmentation | VLAN Configuration",
    ),
    (
        "22",
        "Access only",
        [
            "Implement access-only restrictions for specified information",
            "Configure systems to prevent copying or downloading restricted data",
            "Enable watermarking and view-only access for sensitive documents",
            "Monitor for bypass attempts of access-only controls",
        ],
        "DRM > Access Only Policies",
    ),
    (
        "23",
        "Modify non-releasable information",
        [
            "Implement automated redaction of non-releasable content",
            "Configure content transformation rules for cross-domain releases",
            "Verify redaction completeness before information release",
            "Test redaction effectiveness with known non-releasable data",
        ],
        "DLP > Redaction Rules",
    ),
    (
        "24",
        "Internal normalized format",
        [
            "Define internal normalized data formats for cross-boundary transfers",
            "Implement format conversion at trust boundaries",
            "Validate data integrity after format conversion",
            "Document supported format conversions",
        ],
        "Data Pipeline > Format Transformation",
    ),
    (
        "25",
        "Data sanitization",
        [
            "Implement data sanitization at information flow boundaries",
            "Configure content disarm and reconstruction (CDR)",
            "Remove executable content from transferred files",
            "Validate sanitization effectiveness through testing",
        ],
        "Email Security > CDR | File Upload > Sanitization",
    ),
    (
        "26",
        "Audit filtering actions",
        [
            "Enable comprehensive audit logging for all filter actions",
            "Log filter decisions including allow, block, and quarantine",
            "Forward filter audit logs to SIEM",
            "Review filter audit logs for anomalies weekly",
        ],
        "SIEM > Filter Action Logs",
    ),
    (
        "27",
        "Redundant or independent filtering mechanisms",
        [
            "Deploy redundant filtering at multiple network layers",
            "Implement independent filtering mechanisms from different vendors",
            "Configure failover between redundant filters",
            "Test filter redundancy annually",
        ],
        "Network > Defense in Depth > Filter Layers",
    ),
    (
        "28",
        "Linear filter pipelines",
        [
            "Implement linear processing pipelines for content filtering",
            "Ensure filters process in defined order without bypass capability",
            "Verify pipeline integrity and completeness",
            "Document filter pipeline processing order",
        ],
        "Security Pipeline > Filter Chain Configuration",
    ),
    (
        "29",
        "Filter orchestration engines",
        [
            "Deploy orchestration engine to manage filter processing",
            "Configure automated filter selection based on content type",
            "Monitor orchestration engine health and performance",
            "Test orchestration failover procedures",
        ],
        "Security Orchestration > Filter Management",
    ),
    (
        "30",
        "Filter mechanisms using multiple processes",
        [
            "Implement filter processing across multiple isolated processes",
            "Configure process isolation for filter execution",
            "Monitor individual filter process health",
            "Implement automatic process restart on failure",
        ],
        "Container Orchestration > Filter Services",
    ),
    (
        "31",
        "Failed content transfer prevention",
        [
            "Configure fail-closed behavior for content transfer failures",
            "Implement retry with escalation for failed transfers",
            "Alert on repeated content transfer failures",
            "Log all failed transfer attempts",
        ],
        "DLP > Incident Management > Failed Transfers",
    ),
    (
        "32",
        "Process requirements for information transfer",
        [
            "Define process requirements for each information transfer type",
            "Implement automated compliance checking for transfer processes",
            "Verify process requirements before allowing transfers",
            "Audit process compliance for information transfers quarterly",
        ],
        "Workflow > Transfer Process Compliance",
    ),
]:
    CONTROLS[f"AC-4({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-4({enh}) Assessment Procedures"],
        "evidence_types": ["config_snapshots", "network_flow_logs"],
    }

CONTROLS["AC-5"] = {
    "summary": "Enforce separation of duties through assigned access authorizations",
    "remediation_steps": [
        "Identify duties requiring separation (e.g., development vs deployment, approval vs execution)",
        "Implement role separation in IAM policies",
        "Configure SoD rules in identity governance platform",
        "Review and test SoD enforcement quarterly",
    ],
    "console_path": "SailPoint > Access Policies > SoD Rules",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-5 Assessment Procedures"],
    "evidence_types": ["sailpoint_roles", "iam_policies"],
}

CONTROLS["AC-5(1)"] = {
    "summary": "Document separation of duties",
    "remediation_steps": [
        "Document all identified separation of duty requirements",
        "Map SoD requirements to organizational roles",
        "Maintain SoD matrix and review annually",
        "Verify SoD documentation matches implemented controls",
    ],
    "console_path": "Confluence > SEC Space > SoD Matrix",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-5(1) Assessment Procedures"],
    "evidence_types": ["policy_document"],
}

CONTROLS["AC-6"] = {
    "summary": "Employ the principle of least privilege allowing only authorized access needed for job functions",
    "remediation_steps": [
        "Review IAM policies for overprivileged access",
        "Remove administrative access keys from root account",
        "Implement permission boundaries on IAM roles",
        "Use IAM Access Analyzer to identify unused permissions",
        "Configure CyberArk for privileged access management",
    ],
    "console_path": "IAM > Access Analyzer > Findings | CyberArk > Accounts",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-6 Assessment Procedures",
        "CIS AWS Foundations Benchmark: 1.16",
    ],
    "evidence_types": ["iam_users", "iam_policies", "cyberark_accounts"],
}

for enh, summ, steps, cp in [
    (
        "1",
        "Authorize access to security functions",
        [
            "Identify all security functions and their authorized users",
            "Restrict security function access to designated security personnel",
            "Implement separate authentication for security function access",
            "Audit security function access monthly",
        ],
        "IAM > Roles > SecurityAdministrator",
    ),
    (
        "2",
        "Non-privileged access for non-security functions",
        [
            "Configure non-privileged accounts for non-security tasks",
            "Require administrators to use non-privileged accounts for daily work",
            "Implement account type separation in directory services",
            "Monitor for privileged account use in non-security contexts",
        ],
        "Entra ID > Users > Account Type Separation",
    ),
    (
        "3",
        "Network access to privileged commands",
        [
            "Restrict network access to privileged commands to authorized endpoints",
            "Configure PAM jump servers for remote privileged access",
            "Block direct SSH/RDP to production from untrusted networks",
            "Log all network-based privileged command execution",
        ],
        "VPC > Security Groups > Management Access",
    ),
    (
        "4",
        "Separate processing domains",
        [
            "Implement separate processing environments for different privilege levels",
            "Configure network segmentation between processing domains",
            "Restrict inter-domain communication to defined interfaces",
            "Monitor cross-domain privilege usage",
        ],
        "VPC > Subnets > Domain Isolation",
    ),
    (
        "5",
        "Privileged accounts",
        [
            "Restrict privileged accounts to specific authorized users",
            "Implement multi-factor authentication for all privileged accounts",
            "Configure session recording for privileged access",
            "Review privileged account inventory monthly",
        ],
        "CyberArk > Privileged Accounts | IAM > Root Account",
    ),
    (
        "6",
        "Privileged access by non-organizational users",
        [
            "Prohibit or strictly limit privileged access by external users",
            "Require additional approval for vendor privileged access",
            "Implement time-bound access for external privileged users",
            "Monitor all external privileged access sessions",
        ],
        "IAM > External Roles | CyberArk > Vendor Access",
    ),
    (
        "7",
        "Review of user privileges",
        [
            "Conduct quarterly review of all user privileges",
            "Implement automated privilege review campaigns in IGA tool",
            "Revoke unnecessary privileges identified during review",
            "Document review results and remediation actions",
        ],
        "SailPoint > Certifications | Okta > Access Reviews",
    ),
    (
        "8",
        "Privilege levels for code execution",
        [
            "Configure software to execute at minimum required privilege levels",
            "Implement application sandboxing and containerization",
            "Restrict code execution privileges in production environments",
            "Verify application privilege levels in security testing",
        ],
        "Container Platform > Security Context | AppArmor Profiles",
    ),
    (
        "9",
        "Log use of privileged functions",
        [
            "Enable audit logging for all privileged function execution",
            "Forward privileged function logs to SIEM",
            "Configure alerts for unusual privileged function usage",
            "Review privileged function logs weekly",
        ],
        "CloudTrail > Event History > Privileged Actions",
    ),
    (
        "10",
        "Prohibit non-privileged users from executing privileged functions",
        [
            "Implement hard enforcement preventing privilege escalation",
            "Configure sudo policies with explicit allow lists",
            "Enable security modules to prevent unauthorized privilege use",
            "Test privilege escalation prevention controls quarterly",
        ],
        "IAM > Permission Boundaries | Linux > sudoers",
    ),
]:
    CONTROLS[f"AC-6({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-6({enh}) Assessment Procedures"],
        "evidence_types": ["iam_users", "iam_policies", "cyberark_accounts"],
    }

CONTROLS["AC-7"] = {
    "summary": "Enforce a limit on consecutive invalid logon attempts and automatically lock accounts",
    "remediation_steps": [
        "Configure account lockout after 5 consecutive failed logon attempts",
        "Set lockout duration to minimum 30 minutes or require admin unlock",
        "Enable failed logon attempt logging and alerting",
        "Configure lockout policies in all identity providers",
    ],
    "console_path": "Okta > Security > Authentication Policies > Lockout | Entra ID > Password Protection",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-7 Assessment Procedures"],
    "evidence_types": ["okta_policies", "entra_sign_ins"],
}

for enh, summ, steps, cp in [
    (
        "1",
        "Automatic account lock from failed attempts",
        [
            "Configure automatic account lock after failed attempt threshold",
            "Set progressive lockout durations",
            "Enable notification to administrators on account lockout",
            "Verify lockout policies apply to all account types",
        ],
        "Okta > Security > Account Lockout Policy",
    ),
    (
        "2",
        "Purge or wipe device after failed logon attempts",
        [
            "Configure mobile device management to wipe after excessive failed attempts",
            "Set failed attempt threshold for device wipe (10 attempts recommended)",
            "Enable remote wipe capability for all managed devices",
            "Document device wipe procedures and data recovery process",
        ],
        "Intune > Device Compliance > Wipe Policy",
    ),
    (
        "3",
        "Biometric attempt limiting",
        [
            "Configure biometric authentication to lock after failed attempts",
            "Set fallback authentication method after biometric failure",
            "Implement anti-spoofing measures for biometric authentication",
            "Log biometric authentication failures",
        ],
        "Device Management > Biometric Policies",
    ),
    (
        "4",
        "Use of alternate factor for account unlock",
        [
            "Configure alternate authentication factor for account unlock",
            "Implement self-service account unlock with MFA verification",
            "Require different factor type than the one that triggered lockout",
            "Log all account unlock activities",
        ],
        "Okta > Self-Service > Account Unlock",
    ),
]:
    CONTROLS[f"AC-7({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-7({enh}) Assessment Procedures"],
        "evidence_types": ["okta_policies", "entra_conditional_access_policies"],
    }

CONTROLS["AC-8"] = {
    "summary": "Display system use notification message before granting access",
    "remediation_steps": [
        "Configure login banners on all systems with approved use notification",
        "Include privacy and monitoring notice in system use notification",
        "Require user acknowledgment before granting access",
        "Verify banner display on all access methods (SSH, RDP, web, VPN)",
    ],
    "console_path": "EC2 > Instance > SSH Banner | GPO > Login Message",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-8 Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AC-8(1)"] = {
    "summary": "System use notification details",
    "remediation_steps": [
        "Include specific language about authorized use, monitoring, and consequences",
        "Obtain legal review of system use notification text",
        "Ensure notification is displayed before authentication prompt",
        "Document notification content and approval history",
    ],
    "console_path": "System Configuration > Login Banner",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-8(1) Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AC-9"] = {
    "summary": "Notify user upon successful logon of previous logon information",
    "remediation_steps": [
        "Configure systems to display previous logon date, time, and location",
        "Enable successful logon notification in identity provider",
        "Display number of unsuccessful logon attempts since last successful logon",
        "Implement notification for logons from new devices or locations",
    ],
    "console_path": "Okta > Security > Notification Policies | Entra ID > Sign-in Notifications",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-9 Assessment Procedures"],
    "evidence_types": ["okta_system_log", "entra_sign_ins"],
}

CONTROLS["AC-10"] = {
    "summary": "Limit the number of concurrent sessions for each account",
    "remediation_steps": [
        "Configure concurrent session limits per user (3 sessions recommended)",
        "Implement session management in identity provider",
        "Configure web application session limits",
        "Alert on concurrent session limit violations",
    ],
    "console_path": "Okta > Security > Global Session Policy > Max Sessions",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-10 Assessment Procedures"],
    "evidence_types": ["okta_policies"],
}

CONTROLS["AC-10(1)"] = {
    "summary": "Concurrent session control by account type",
    "remediation_steps": [
        "Define session limits per account type (user, admin, service)",
        "Configure stricter limits for privileged account sessions",
        "Implement session limit enforcement across all access methods",
        "Monitor and alert on session limit exceptions",
    ],
    "console_path": "Okta > Security > Session Policies > Per Role",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-10(1) Assessment Procedures"],
    "evidence_types": ["okta_policies"],
}

CONTROLS["AC-11"] = {
    "summary": "Initiate a session lock after a period of inactivity",
    "remediation_steps": [
        "Configure screen lock after 15 minutes of inactivity",
        "Enforce session lock via MDM policies on all endpoints",
        "Configure application session timeout",
        "Verify session lock applies to all device types",
    ],
    "console_path": "Intune > Configuration Profiles > Screen Lock | GPO > Screen Saver",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-11 Assessment Procedures"],
    "evidence_types": ["intune_devices", "config_snapshots"],
}

CONTROLS["AC-11(1)"] = {
    "summary": "Pattern-hiding displays for session lock",
    "remediation_steps": [
        "Configure screen lock to conceal information previously visible",
        "Enable screen saver or lock screen that hides display content",
        "Verify pattern-hiding on all device types",
        "Test that no sensitive information is visible on locked screens",
    ],
    "console_path": "Intune > Configuration Profiles > Lock Screen Settings",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-11(1) Assessment Procedures"],
    "evidence_types": ["intune_devices"],
}

CONTROLS["AC-12"] = {
    "summary": "Automatically terminate a user session after defined conditions",
    "remediation_steps": [
        "Configure automatic session termination after maximum session duration",
        "Implement session termination on security policy violation",
        "Set absolute session timeout (8 hours recommended)",
        "Enable forced logout capability for security incidents",
    ],
    "console_path": "Okta > Security > Global Session Policy > Max Lifetime",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-12 Assessment Procedures"],
    "evidence_types": ["okta_policies", "entra_conditional_access_policies"],
}

for enh, summ, steps, cp in [
    (
        "1",
        "User-initiated logouts",
        [
            "Provide visible logout mechanism in all applications",
            "Implement session cleanup on user logout",
            "Verify token revocation on logout",
            "Confirm logout terminates all related sessions",
        ],
        "Application > Session Management > Logout",
    ),
    (
        "2",
        "Termination message",
        [
            "Display logout confirmation message to user",
            "Include session duration in termination message",
            "Verify message displays consistently across all access methods",
        ],
        "Application > Session Management > Logout Message",
    ),
    (
        "3",
        "Timeout warning message",
        [
            "Display session timeout warning before automatic termination",
            "Provide option to extend session before timeout",
            "Configure warning interval (5 minutes before timeout recommended)",
        ],
        "Application > Session Management > Timeout Warning",
    ),
]:
    CONTROLS[f"AC-12({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-12({enh}) Assessment Procedures"],
        "evidence_types": ["config_snapshots"],
    }

CONTROLS["AC-13"] = {
    "summary": "Supervision and review of access control (withdrawn - incorporated into AC-2 and AU-6)",
    "remediation_steps": [
        "This control has been withdrawn and incorporated into AC-2 and AU-6",
        "Verify AC-2 account management controls are implemented",
        "Verify AU-6 audit record review controls are implemented",
    ],
    "console_path": "See AC-2 and AU-6",
    "recommended_reading": ["NIST SP 800-53 Rev 5: AC-13 Withdrawal Notice"],
    "evidence_types": ["policy_document"],
}

CONTROLS["AC-14"] = {
    "summary": "Permitted actions without identification or authentication",
    "remediation_steps": [
        "Identify and document actions permitted without authentication",
        "Minimize unauthenticated access to essential public functions only",
        "Review permitted unauthenticated actions quarterly",
        "Monitor unauthenticated access for abuse patterns",
    ],
    "console_path": "Application > Public Endpoints | API Gateway > Unauthenticated Routes",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-14 Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AC-14(1)"] = {
    "summary": "Necessary uses for permitted actions",
    "remediation_steps": [
        "Document necessity justification for each unauthenticated action",
        "Review justifications annually with system owner",
        "Remove unnecessary unauthenticated access",
    ],
    "console_path": "Confluence > SEC Space > Unauthenticated Access Register",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-14(1) Assessment Procedures"],
    "evidence_types": ["policy_document"],
}

CONTROLS["AC-15"] = {
    "summary": "Automated marking (withdrawn - incorporated into MP-3)",
    "remediation_steps": [
        "This control has been withdrawn and incorporated into MP-3",
        "Verify MP-3 media marking controls are implemented",
    ],
    "console_path": "See MP-3",
    "recommended_reading": ["NIST SP 800-53 Rev 5: AC-15 Withdrawal Notice"],
    "evidence_types": ["policy_document"],
}

CONTROLS["AC-16"] = {
    "summary": "Security and privacy attributes associated with information",
    "remediation_steps": [
        "Define security and privacy attribute schema for organizational information",
        "Implement automated attribute assignment on data creation",
        "Configure attribute-based access control using defined attributes",
        "Verify attribute persistence across system boundaries",
    ],
    "console_path": "Microsoft Purview > Sensitivity Labels | Data Classification",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-16 Assessment Procedures"],
    "evidence_types": ["config_snapshots", "dlp_policies"],
}

for enh in range(1, 11):
    names = {
        1: "Dynamic attribute association",
        2: "Attribute value changes by authorized individuals",
        3: "Maintenance of attribute associations by system",
        4: "Association of attributes by authorized individuals",
        5: "Attribute displays on objects or information",
        6: "Maintenance of attribute association",
        7: "Consistent attribute interpretation",
        8: "Association techniques and technologies",
        9: "Attribute reassignment mechanisms",
        10: "Attribute configuration by authorized individuals",
    }
    CONTROLS[f"AC-16({enh})"] = {
        "summary": names[enh],
        "remediation_steps": [
            f"Implement {names[enh].lower()} mechanisms",
            "Configure attribute management in data classification tool",
            "Verify attribute integrity through automated testing",
            "Audit attribute management operations monthly",
        ],
        "console_path": "Microsoft Purview > Data Classification > Attributes",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-16({enh}) Assessment Procedures"],
        "evidence_types": ["config_snapshots"],
    }

CONTROLS["AC-17"] = {
    "summary": "Establish and document usage restrictions and implementation guidance for remote access",
    "remediation_steps": [
        "Implement VPN or zero-trust network access for remote connections",
        "Configure security groups to restrict remote access ports",
        "Require MFA for all remote access sessions",
        "Monitor and log all remote access connections",
    ],
    "console_path": "VPC > Security Groups > Remote Access | VPN > Configuration",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-17 Assessment Procedures",
        "NIST SP 800-46: Telework Security Guide",
    ],
    "evidence_types": ["ec2_security_groups", "network_security_groups", "okta_system_log"],
}

for enh, summ, steps, cp in [
    (
        "1",
        "Monitoring and control of remote access",
        [
            "Implement automated monitoring of remote access sessions",
            "Configure alerts for unusual remote access patterns",
            "Enable session recording for privileged remote access",
            "Review remote access logs weekly",
        ],
        "SIEM > Remote Access Dashboard",
    ),
    (
        "2",
        "Protection of confidentiality and integrity using encryption",
        [
            "Require TLS 1.2 or higher for all remote access",
            "Configure VPN with AES-256 encryption",
            "Implement certificate-based VPN authentication",
            "Verify encryption strength in remote access configurations",
        ],
        "VPN > Encryption Settings | TLS Configuration",
    ),
    (
        "3",
        "Managed access control points",
        [
            "Route all remote access through managed access control points",
            "Configure centralized VPN concentrators or ZTNA gateways",
            "Prohibit direct remote access bypassing control points",
            "Monitor for unauthorized remote access paths",
        ],
        "Network > VPN Concentrators | ZTNA Gateway",
    ),
    (
        "4",
        "Privileged commands and access",
        [
            "Restrict privileged commands over remote access to authorized users",
            "Implement PAM for remote privileged access",
            "Document business justification for remote privileged access",
            "Audit remote privileged command execution weekly",
        ],
        "CyberArk > Remote Access > Privileged Sessions",
    ),
    (
        "5",
        "Monitoring for unauthorized connections",
        [
            "Enable detection of unauthorized remote connections",
            "Configure IDS/IPS for unauthorized connection detection",
            "Alert on remote connections from unapproved locations",
            "Review unauthorized connection reports daily",
        ],
        "GuardDuty > Remote Connection Findings",
    ),
    (
        "6",
        "Protection of mechanism information",
        [
            "Protect remote access mechanism configuration details",
            "Encrypt VPN configuration files and credentials",
            "Restrict access to remote access infrastructure",
            "Audit access to remote access configurations",
        ],
        "VPN > Configuration > Access Controls",
    ),
    (
        "7",
        "Additional protection for security function access",
        [
            "Require additional authentication for remote security administration",
            "Implement step-up authentication for security functions",
            "Restrict remote security function access to approved endpoints",
            "Monitor remote security administration sessions",
        ],
        "PAM > Step-Up Authentication",
    ),
    (
        "8",
        "Disable nonsecure network protocols",
        [
            "Disable telnet, FTP, HTTP, and other unencrypted protocols for remote access",
            "Configure firewalls to block insecure remote access protocols",
            "Enable only SSH, HTTPS, and encrypted VPN for remote management",
            "Scan for insecure remote access protocols monthly",
        ],
        "Network > Protocol Configuration",
    ),
    (
        "9",
        "Disconnect or disable remote access",
        [
            "Implement capability to immediately disconnect remote access",
            "Configure kill switch for remote access in security incidents",
            "Document remote access disconnect procedures",
            "Test remote access disconnect capability quarterly",
        ],
        "VPN > Emergency Disconnect | ZTNA > Kill Switch",
    ),
    (
        "10",
        "Authenticate remote commands",
        [
            "Implement command authentication for remote management",
            "Configure signed commands for remote execution",
            "Verify command integrity before execution",
            "Log all remote command authentication events",
        ],
        "SSM > Run Command > Authentication",
    ),
]:
    CONTROLS[f"AC-17({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-17({enh}) Assessment Procedures"],
        "evidence_types": ["ec2_security_groups", "network_security_groups", "vpn_config"],
    }

CONTROLS["AC-18"] = {
    "summary": "Establish usage restrictions and implementation guidance for wireless access",
    "remediation_steps": [
        "Document wireless access policy including authorized devices and networks",
        "Configure WPA3 Enterprise for all organizational wireless networks",
        "Implement wireless IDS/IPS to detect rogue access points",
        "Restrict wireless access to authenticated and authorized users only",
    ],
    "console_path": "Network > Wireless Controller > Security Policies",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-18 Assessment Procedures"],
    "evidence_types": ["config_snapshots", "network_scans"],
}

for enh, summ, steps in [
    (
        "1",
        "Authentication and encryption for wireless",
        [
            "Require WPA3 or WPA2-Enterprise with 802.1X authentication",
            "Configure certificate-based wireless authentication",
            "Disable legacy wireless protocols (WEP, WPA-PSK)",
            "Monitor wireless networks for encryption downgrades",
        ],
    ),
    (
        "2",
        "Monitoring for unauthorized wireless connections",
        [
            "Deploy wireless IDS to detect rogue access points",
            "Configure automated alerting for unauthorized wireless devices",
            "Conduct wireless site surveys quarterly",
            "Block unauthorized wireless devices detected on network",
        ],
    ),
    (
        "3",
        "Disable wireless networking",
        [
            "Disable wireless interfaces on systems that do not require wireless access",
            "Configure BIOS/firmware to disable wireless hardware where possible",
            "Implement MDM policies to control wireless interface state",
            "Verify wireless is disabled on sensitive systems monthly",
        ],
    ),
    (
        "4",
        "Restrict configurations by users",
        [
            "Restrict user ability to modify wireless configurations",
            "Manage wireless profiles centrally via MDM",
            "Prevent users from connecting to unapproved wireless networks",
            "Audit wireless configuration changes",
        ],
    ),
    (
        "5",
        "Antennas and transmission power levels",
        [
            "Configure wireless transmission power to limit signal outside facility",
            "Use directional antennas to control wireless coverage area",
            "Verify wireless signal containment through site surveys",
            "Document antenna configuration and justification",
        ],
    ),
]:
    CONTROLS[f"AC-18({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "Network > Wireless Controller > Configuration",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-18({enh}) Assessment Procedures"],
        "evidence_types": ["config_snapshots", "network_scans"],
    }

CONTROLS["AC-19"] = {
    "summary": "Establish usage restrictions and implementation guidance for mobile devices",
    "remediation_steps": [
        "Implement MDM solution for all organizational mobile devices",
        "Configure device compliance policies (encryption, PIN, OS version)",
        "Enable remote wipe capability for lost or stolen devices",
        "Require device enrollment before accessing organizational resources",
    ],
    "console_path": "Intune > Devices > Compliance Policies | Jamf > Policies",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AC-19 Assessment Procedures",
        "NIST SP 800-124: Mobile Device Security",
    ],
    "evidence_types": ["intune_devices", "jamf_devices"],
}

for enh, summ, steps in [
    (
        "1",
        "Use of writable and portable storage devices",
        [
            "Restrict use of portable storage on mobile devices",
            "Configure DLP policies for mobile data transfer",
            "Disable USB mass storage on managed mobile devices",
            "Monitor mobile device storage usage",
        ],
    ),
    (
        "2",
        "Use of personally owned portable storage devices",
        [
            "Prohibit or restrict use of personal storage devices",
            "Implement BYOD containerization policies",
            "Configure data loss prevention for personal devices",
            "Document personal device storage restrictions",
        ],
    ),
    (
        "3",
        "Use of portable storage devices with no identifiable owner",
        [
            "Prohibit use of unowned portable storage devices",
            "Implement USB device whitelisting",
            "Configure endpoint protection to block unknown USB devices",
            "Train users on risks of unknown storage devices",
        ],
    ),
    (
        "4",
        "Restrictions for classified information",
        [
            "Prohibit classified information on mobile devices unless specifically authorized",
            "Implement mobile device containers for classified data",
            "Configure enhanced encryption for classified mobile data",
            "Audit classified data handling on mobile devices",
        ],
    ),
    (
        "5",
        "Full device or container-based encryption",
        [
            "Enable full device encryption on all mobile devices",
            "Configure application container encryption for BYOD",
            "Verify encryption status through MDM compliance checks",
            "Block access for devices not meeting encryption requirements",
        ],
    ),
]:
    CONTROLS[f"AC-19({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "Intune > Device Compliance > Mobile Policies",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-19({enh}) Assessment Procedures"],
        "evidence_types": ["intune_devices", "jamf_devices"],
    }

CONTROLS["AC-20"] = {
    "summary": "Establish terms and conditions for use of external systems",
    "remediation_steps": [
        "Document acceptable use policies for external systems",
        "Implement conditional access policies for external system access",
        "Require security assessment of external systems before connection",
        "Review external system authorizations annually",
    ],
    "console_path": "Entra ID > External Identities > Cross-Tenant Access",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-20 Assessment Procedures"],
    "evidence_types": ["config_snapshots", "policy_document"],
}

for enh, summ, steps in [
    (
        "1",
        "Limits on authorized use",
        [
            "Define specific limits on how external systems may access organizational data",
            "Configure data sharing policies for external collaborators",
            "Implement time-limited external system access",
            "Monitor external system usage patterns",
        ],
    ),
    (
        "2",
        "Portable storage devices on external systems",
        [
            "Restrict use of organizational portable storage on external systems",
            "Configure DLP for external system data transfers",
            "Document approved external system data exchange methods",
            "Train users on portable storage risks with external systems",
        ],
    ),
    (
        "3",
        "Non-organizationally owned systems as components",
        [
            "Assess security posture of non-owned systems used as components",
            "Implement monitoring for non-owned system connections",
            "Require compliance verification for non-owned components",
            "Document risk acceptance for non-owned system use",
        ],
    ),
    (
        "4",
        "Network accessible storage devices as components",
        [
            "Inventory all network-accessible storage in use",
            "Implement access controls on network storage devices",
            "Encrypt data on network-accessible storage",
            "Monitor network storage access patterns",
        ],
    ),
]:
    CONTROLS[f"AC-20({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "Entra ID > External Identities | CASB > Connected Apps",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-20({enh}) Assessment Procedures"],
        "evidence_types": ["config_snapshots"],
    }

CONTROLS["AC-21"] = {
    "summary": "Facilitate information sharing enabling authorized users to share information",
    "remediation_steps": [
        "Implement data sharing policies and access control mechanisms",
        "Configure collaboration tools with appropriate sharing restrictions",
        "Enable data classification labels to guide sharing decisions",
        "Monitor sharing activities for policy violations",
    ],
    "console_path": "Microsoft Purview > Data Sharing | Google Workspace > Sharing Settings",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-21 Assessment Procedures"],
    "evidence_types": ["config_snapshots", "dlp_policies"],
}

CONTROLS["AC-22"] = {
    "summary": "Publicly accessible content management",
    "remediation_steps": [
        "Designate authorized individuals to post publicly accessible content",
        "Review publicly accessible content for sensitive information before posting",
        "Implement content review workflows for public-facing systems",
        "Monitor publicly accessible content for unauthorized modifications",
    ],
    "console_path": "CMS > Content Approval Workflow | S3 > Public Access",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-22 Assessment Procedures"],
    "evidence_types": ["s3_buckets", "config_snapshots"],
}

CONTROLS["AC-22(1)"] = {
    "summary": "Automated review of publicly accessible content",
    "remediation_steps": [
        "Implement automated scanning of public content for sensitive data",
        "Configure DLP scanning on public-facing storage and websites",
        "Set up alerts for sensitive data detected in public content",
        "Review automated scan results weekly",
    ],
    "console_path": "Macie > Public Bucket Scans | DLP > Public Content",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-22(1) Assessment Procedures"],
    "evidence_types": ["s3_buckets", "macie_findings"],
}

CONTROLS["AC-23"] = {
    "summary": "Data mining protection",
    "remediation_steps": [
        "Implement query limiting and result set restrictions",
        "Configure database activity monitoring for data mining patterns",
        "Enable rate limiting on data access APIs",
        "Alert on bulk data extraction attempts",
    ],
    "console_path": "Database > Activity Monitoring | API Gateway > Rate Limiting",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-23 Assessment Procedures"],
    "evidence_types": ["config_snapshots", "audit_logs"],
}

CONTROLS["AC-24"] = {
    "summary": "Access control decisions based on security and privacy attributes",
    "remediation_steps": [
        "Implement attribute-based access control decision engine",
        "Configure real-time attribute evaluation for access decisions",
        "Integrate attribute sources (directory, classification, risk) into decision points",
        "Test access decision accuracy with representative scenarios",
    ],
    "console_path": "OPA > Policy Decision Point | IAM > Access Analyzer",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-24 Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

for enh, summ, steps in [
    (
        "1",
        "Transmit access authorization information",
        [
            "Implement token-based authorization with attribute claims",
            "Configure JWT or SAML assertions with access attributes",
            "Verify attribute transmission integrity with signatures",
            "Audit authorization information transmission",
        ],
    ),
    (
        "2",
        "No user or process identity",
        [
            "Implement attribute-only access decisions without identity",
            "Configure anonymous access based on verified attributes",
            "Verify access decisions are based solely on presented attributes",
            "Test attribute-only access decision scenarios",
        ],
    ),
]:
    CONTROLS[f"AC-24({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "Identity Provider > Token Configuration",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AC-24({enh}) Assessment Procedures"],
        "evidence_types": ["config_snapshots"],
    }

CONTROLS["AC-25"] = {
    "summary": "Reference monitor for access control enforcement",
    "remediation_steps": [
        "Implement tamperproof access control reference monitor",
        "Ensure reference monitor mediates all access to objects",
        "Verify reference monitor cannot be bypassed",
        "Test reference monitor enforcement completeness",
    ],
    "console_path": "Security Architecture > Reference Monitor",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AC-25 Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

# ============================================================
# AT — Awareness and Training
# ============================================================

CONTROLS["AT-1"] = {
    "summary": "Develop, document, and disseminate security and privacy awareness and training policy",
    "remediation_steps": [
        "Draft security awareness and training policy",
        "Define training requirements by role and access level",
        "Establish annual training review and update cycle",
        "Distribute policy to all organizational personnel",
    ],
    "console_path": "Confluence > SEC Space > Security Training Policy",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AT-1 Assessment Procedures",
        "NIST SP 800-50: Building an IT Security Awareness and Training Program",
    ],
    "evidence_types": ["policy_document", "policy_review_date"],
}

CONTROLS["AT-2"] = {
    "summary": "Provide security and privacy awareness training to all users",
    "remediation_steps": [
        "Deploy security awareness training platform (KnowBe4, Proofpoint)",
        "Require annual security awareness training for all personnel",
        "Track training completion rates and follow up on non-compliance",
        "Include phishing simulation exercises in training program",
        "Achieve minimum 90% completion rate",
    ],
    "console_path": "KnowBe4 > Training > Campaigns | Proofpoint > SAT",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AT-2 Assessment Procedures",
        "NIST SP 800-50: Security Awareness Training",
    ],
    "evidence_types": ["training_records", "phishing_results"],
}

for enh, summ, steps in [
    (
        "1",
        "Practical exercises in awareness training",
        [
            "Include hands-on security exercises in training program",
            "Conduct tabletop exercises for security scenarios",
            "Implement simulated phishing campaigns monthly",
            "Track practical exercise participation and scores",
        ],
    ),
    (
        "2",
        "Insider threat awareness",
        [
            "Include insider threat module in security awareness training",
            "Train on indicators of insider threat behavior",
            "Provide reporting channels for suspected insider threats",
            "Update insider threat training content annually",
        ],
    ),
    (
        "3",
        "Social engineering and mining awareness",
        [
            "Include social engineering recognition in training",
            "Train on phishing, pretexting, and baiting techniques",
            "Conduct social engineering simulation exercises",
            "Report social engineering attempt metrics",
        ],
    ),
    (
        "4",
        "Suspicious communications and anomalous behavior",
        [
            "Train users to recognize and report suspicious communications",
            "Provide clear reporting procedures for anomalous behavior",
            "Include real-world examples in training materials",
            "Track suspicious communication reports",
        ],
    ),
    (
        "5",
        "Advanced persistent threats",
        [
            "Include APT awareness in security training for high-risk roles",
            "Train on APT indicators and attack lifecycle",
            "Provide role-specific APT awareness for IT and security teams",
            "Update APT training with current threat intelligence",
        ],
    ),
]:
    CONTROLS[f"AT-2({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "KnowBe4 > Training > Modules",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AT-2({enh}) Assessment Procedures"],
        "evidence_types": ["training_records", "phishing_results"],
    }

CONTROLS["AT-3"] = {
    "summary": "Provide role-based security and privacy training to personnel with assigned security roles",
    "remediation_steps": [
        "Identify roles requiring specialized security training",
        "Develop role-specific training content for security personnel, developers, and administrators",
        "Track role-based training completion and certification",
        "Update role-based training content annually",
    ],
    "console_path": "KnowBe4 > Training > Role-Based Campaigns",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AT-3 Assessment Procedures"],
    "evidence_types": ["training_records"],
}

for enh, summ, steps in [
    (
        "1",
        "Environmental controls training",
        [
            "Train facility management on environmental control systems",
            "Include HVAC, fire suppression, and water damage response",
            "Conduct environmental emergency response drills",
            "Update environmental training content annually",
        ],
    ),
    (
        "2",
        "Physical security controls training",
        [
            "Train security personnel on physical security systems",
            "Include access control system operation and monitoring",
            "Conduct physical security incident response training",
            "Update physical security training annually",
        ],
    ),
    (
        "3",
        "Practical exercises in role-based training",
        [
            "Include hands-on labs in role-based security training",
            "Conduct CTF or red team exercises for security teams",
            "Implement incident response tabletop exercises",
            "Track practical exercise completion and performance",
        ],
    ),
    (
        "4",
        "Suspicious communications and anomalous behavior",
        [
            "Provide advanced suspicious communication recognition training for security roles",
            "Train security teams on anomaly detection and investigation",
            "Include threat hunting exercises",
            "Update training with current threat patterns",
        ],
    ),
    (
        "5",
        "Accessing personally identifiable information",
        [
            "Train personnel who access PII on privacy requirements",
            "Include data handling and minimization practices",
            "Provide privacy breach notification procedures training",
            "Track PII-specific training compliance",
        ],
    ),
]:
    CONTROLS[f"AT-3({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "KnowBe4 > Training > Specialized Modules",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AT-3({enh}) Assessment Procedures"],
        "evidence_types": ["training_records"],
    }

CONTROLS["AT-4"] = {
    "summary": "Document and monitor security and privacy training activities",
    "remediation_steps": [
        "Maintain training records for all personnel",
        "Track training completion dates and certification status",
        "Generate training compliance reports monthly",
        "Archive training records per retention policy",
    ],
    "console_path": "KnowBe4 > Reports > Training Completion",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AT-4 Assessment Procedures"],
    "evidence_types": ["training_records"],
}

CONTROLS["AT-5"] = {
    "summary": "Contact with security groups and associations (withdrawn - incorporated into PM-15)",
    "remediation_steps": [
        "This control has been withdrawn and incorporated into PM-15",
        "Verify PM-15 security contacts and groups controls are implemented",
    ],
    "console_path": "See PM-15",
    "recommended_reading": ["NIST SP 800-53 Rev 5: AT-5 Withdrawal Notice"],
    "evidence_types": ["policy_document"],
}

CONTROLS["AT-6"] = {
    "summary": "Training feedback",
    "remediation_steps": [
        "Implement training feedback collection mechanism",
        "Analyze training effectiveness metrics",
        "Update training content based on feedback",
        "Report training effectiveness to management quarterly",
    ],
    "console_path": "KnowBe4 > Reports > Training Effectiveness",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AT-6 Assessment Procedures"],
    "evidence_types": ["training_records"],
}

for enh, summ, steps in [
    (
        "1",
        "Training feedback — awareness training",
        [
            "Collect feedback after each awareness training session",
            "Measure knowledge retention through post-training quizzes",
            "Adjust training content based on feedback trends",
            "Report awareness training effectiveness metrics",
        ],
    ),
    (
        "2",
        "Training feedback — role-based training",
        [
            "Collect feedback after each role-based training module",
            "Assess practical skill improvement through exercises",
            "Adjust role-based content based on performance data",
            "Report role-based training effectiveness metrics",
        ],
    ),
]:
    CONTROLS[f"AT-6({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "KnowBe4 > Reports > Feedback",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AT-6({enh}) Assessment Procedures"],
        "evidence_types": ["training_records"],
    }

# ============================================================
# AU — Audit and Accountability
# ============================================================

CONTROLS["AU-1"] = {
    "summary": "Develop, document, and disseminate audit and accountability policy and procedures",
    "remediation_steps": [
        "Draft audit and accountability policy defining audit requirements",
        "Define audit log retention periods and storage requirements",
        "Establish audit review responsibilities and frequencies",
        "Distribute policy to all organizational personnel",
    ],
    "console_path": "Confluence > SEC Space > Audit Policy",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-1 Assessment Procedures"],
    "evidence_types": ["policy_document", "policy_review_date"],
}

CONTROLS["AU-2"] = {
    "summary": "Determine that the system is capable of auditing organization-defined events",
    "remediation_steps": [
        "Define auditable events for each system component",
        "Enable CloudTrail in all AWS regions with management and data events",
        "Configure Azure Activity Log and Diagnostic Settings",
        "Enable GCP Cloud Audit Logs for all services",
        "Verify audit event coverage against organizational requirements",
    ],
    "console_path": "CloudTrail > Trails | Azure Monitor > Activity Log | GCP > Audit Logs",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: AU-2 Assessment Procedures",
        "NIST SP 800-92: Guide to Computer Security Log Management",
    ],
    "evidence_types": ["cloudtrail_trails", "audit_logs", "activity_log"],
}

for enh, summ, steps in [
    (
        "1",
        "Compilation of audit records from multiple sources",
        [
            "Configure centralized log aggregation from all systems",
            "Implement SIEM for multi-source audit record compilation",
            "Normalize log formats across sources",
            "Verify completeness of log sources in SIEM",
        ],
    ),
    (
        "2",
        "Selection of audit events by component",
        [
            "Define audit events per system component type",
            "Configure component-specific audit policies",
            "Verify each component generates required audit events",
            "Review component audit configuration quarterly",
        ],
    ),
    (
        "3",
        "Reviews and updates to audited events",
        [
            "Review audited events list annually",
            "Update audit event selection based on threat intelligence",
            "Document changes to audit event configuration",
            "Verify updated events are captured after changes",
        ],
    ),
    (
        "4",
        "Privileged functions audit",
        [
            "Enable audit logging for all privileged function execution",
            "Configure CloudTrail for root account and admin API calls",
            "Alert on privileged function audit failures",
            "Review privileged function audit logs weekly",
        ],
    ),
]:
    CONTROLS[f"AU-2({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "SIEM > Log Sources | CloudTrail > Configuration",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-2({enh}) Assessment Procedures"],
        "evidence_types": ["cloudtrail_trails", "audit_logs"],
    }

CONTROLS["AU-3"] = {
    "summary": "Ensure audit records contain sufficient information to establish what occurred, when, where, source, and outcome",
    "remediation_steps": [
        "Configure audit logs to include event type, timestamp, source, user, and outcome",
        "Verify log format includes all required fields",
        "Enable detailed logging on security-relevant services",
        "Test audit record content completeness",
    ],
    "console_path": "CloudTrail > Event Configuration | SIEM > Log Format",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-3 Assessment Procedures"],
    "evidence_types": ["cloudtrail_trails", "audit_logs"],
}

for enh, summ, steps in [
    (
        "1",
        "Additional audit information",
        [
            "Configure extended audit fields (session ID, network address, object accessed)",
            "Enable CloudTrail data events for S3 and Lambda",
            "Configure database audit logging with query details",
            "Verify additional audit fields are captured",
        ],
    ),
    (
        "2",
        "Centralized management of planned audit record content",
        [
            "Implement centralized audit format standards",
            "Configure log schema enforcement in SIEM",
            "Standardize audit record content across all systems",
            "Review audit content standards annually",
        ],
    ),
    (
        "3",
        "Limit personally identifiable information in audit records",
        [
            "Configure audit logging to minimize PII capture",
            "Implement PII masking in audit records",
            "Define PII fields that must be excluded from logs",
            "Verify PII minimization in audit records",
        ],
    ),
]:
    CONTROLS[f"AU-3({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "SIEM > Log Format > Fields",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-3({enh}) Assessment Procedures"],
        "evidence_types": ["audit_logs"],
    }

CONTROLS["AU-4"] = {
    "summary": "Allocate audit log storage capacity",
    "remediation_steps": [
        "Configure S3 buckets or Azure Blob for audit log storage with sufficient capacity",
        "Set up log lifecycle policies with appropriate retention",
        "Monitor log storage utilization and alert at 80% capacity",
        "Implement log compression and archival for long-term storage",
    ],
    "console_path": "S3 > Audit Log Buckets > Lifecycle | CloudWatch > Log Groups",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-4 Assessment Procedures"],
    "evidence_types": ["s3_buckets", "config_snapshots"],
}

CONTROLS["AU-5"] = {
    "summary": "Alert designated personnel in the event of an audit logging process failure",
    "remediation_steps": [
        "Configure alerts for audit logging failures (CloudTrail disabled, disk full)",
        "Implement redundant audit log destinations",
        "Define incident response procedures for audit failures",
        "Test audit failure alerting quarterly",
    ],
    "console_path": "CloudWatch > Alarms > CloudTrail Status | SIEM > Health Alerts",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-5 Assessment Procedures"],
    "evidence_types": ["cloudwatch_alarms", "config_snapshots"],
}

for enh, summ, steps in [
    (
        "1",
        "Storage capacity warning",
        [
            "Configure alerts when log storage reaches capacity threshold",
            "Set warning at 80% and critical at 90% capacity",
            "Implement automatic log archival to prevent capacity issues",
            "Test storage capacity alerting",
        ],
    ),
    (
        "2",
        "Real-time alerts",
        [
            "Configure real-time alerting for audit processing failures",
            "Implement immediate notification to security operations",
            "Set up PagerDuty or similar for audit failure alerts",
            "Verify alert delivery within defined SLA",
        ],
    ),
    (
        "3",
        "Configurable traffic volume thresholds",
        [
            "Set audit traffic volume thresholds for anomaly detection",
            "Alert on unusual audit volume increases or decreases",
            "Configure baseline audit volume metrics",
            "Investigate volume anomalies within 24 hours",
        ],
    ),
    (
        "4",
        "Shutdown on failure",
        [
            "Configure systems to shut down or degrade gracefully on audit failure",
            "Implement fail-closed audit behavior for critical systems",
            "Document audit failure response procedures",
            "Test system behavior on audit failure",
        ],
    ),
    (
        "5",
        "Alternate audit logging capability",
        [
            "Implement secondary audit log destination for failover",
            "Configure automatic failover to alternate logging",
            "Test alternate audit logging annually",
            "Verify alternate logs capture same events as primary",
        ],
    ),
]:
    CONTROLS[f"AU-5({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "CloudWatch > Alarms | SIEM > Health Monitoring",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-5({enh}) Assessment Procedures"],
        "evidence_types": ["cloudwatch_alarms"],
    }

CONTROLS["AU-6"] = {
    "summary": "Review and analyze audit records for indications of inappropriate or unusual activity",
    "remediation_steps": [
        "Establish audit review procedures and schedule (weekly minimum)",
        "Configure SIEM correlation rules for suspicious activity detection",
        "Assign audit review responsibilities to security operations team",
        "Document findings and escalation procedures",
    ],
    "console_path": "SIEM > Dashboards > Audit Review | Sentinel > Workbooks",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-6 Assessment Procedures"],
    "evidence_types": ["audit_logs", "siem_alerts"],
}

for enh in range(1, 11):
    names = {
        1: "Automated process integration for audit review",
        2: "Automated security alerts",
        3: "Correlate audit record repositories",
        4: "Central review and analysis",
        5: "Integrated analysis of audit records",
        6: "Correlation with physical monitoring",
        7: "Permitted actions",
        8: "Full text analysis of privileged commands",
        9: "Correlation with physical access monitoring",
        10: "Audit level adjustment",
    }
    steps_map = {
        1: [
            "Implement automated audit analysis in SIEM",
            "Configure automated alert generation",
            "Set up scheduled audit review reports",
            "Verify automated analysis coverage",
        ],
        2: [
            "Configure real-time security alerts in SIEM",
            "Set up alert notification channels",
            "Define alert severity levels and response procedures",
            "Test alert delivery monthly",
        ],
        3: [
            "Correlate audit records across multiple log sources",
            "Configure SIEM to cross-reference cloud, network, and application logs",
            "Implement unified correlation rules",
            "Verify cross-source correlation accuracy",
        ],
        4: [
            "Centralize audit review in single SIEM platform",
            "Configure unified dashboards for audit analysis",
            "Implement role-based access to audit review tools",
            "Standardize review procedures across teams",
        ],
        5: [
            "Integrate audit analysis with vulnerability, asset, and threat data",
            "Configure SIEM enrichment with context sources",
            "Implement automated risk scoring for audit events",
            "Review integrated analysis results weekly",
        ],
        6: [
            "Correlate logical audit events with physical access records",
            "Integrate badge reader logs with SIEM",
            "Alert on logical access without corresponding physical presence",
            "Review correlation findings weekly",
        ],
        7: [
            "Define permitted actions after audit review findings",
            "Implement automated response playbooks",
            "Configure approved remediation actions",
            "Track audit finding resolution",
        ],
        8: [
            "Enable full command logging for privileged sessions",
            "Configure session recording for administrative access",
            "Implement command analysis for security violations",
            "Review privileged command logs weekly",
        ],
        9: [
            "Correlate cyber audit logs with physical access monitoring",
            "Integrate video surveillance with logical access events",
            "Alert on suspicious physical-cyber correlations",
            "Review correlation findings weekly",
        ],
        10: [
            "Implement adjustable audit logging levels",
            "Configure dynamic audit level increases during incidents",
            "Enable granular audit control per system component",
            "Document audit level adjustment procedures",
        ],
    }
    CONTROLS[f"AU-6({enh})"] = {
        "summary": names[enh],
        "remediation_steps": steps_map[enh],
        "console_path": "SIEM > Correlation Rules | Sentinel > Analytics",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-6({enh}) Assessment Procedures"],
        "evidence_types": ["audit_logs", "siem_alerts"],
    }

CONTROLS["AU-7"] = {
    "summary": "Provide audit record reduction and report generation capability",
    "remediation_steps": [
        "Implement SIEM dashboards for audit record analysis",
        "Configure report generation for compliance and security review",
        "Enable search and filter capabilities on audit records",
        "Provide audit record export functionality",
    ],
    "console_path": "SIEM > Reports | Sentinel > Workbooks | Splunk > Dashboards",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-7 Assessment Procedures"],
    "evidence_types": ["siem_config"],
}

for enh, summ, steps in [
    (
        "1",
        "Automatic processing",
        [
            "Configure automated audit record processing and analysis",
            "Implement scheduled report generation",
            "Enable automated trend analysis on audit data",
            "Verify automated processing completeness",
        ],
    ),
    (
        "2",
        "Automatic sort and search",
        [
            "Enable full-text search across all audit records",
            "Configure indexed search for rapid audit record retrieval",
            "Implement sort capabilities by date, user, event type, and severity",
            "Test search performance and accuracy",
        ],
    ),
]:
    CONTROLS[f"AU-7({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "SIEM > Search | Sentinel > Logs",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-7({enh}) Assessment Procedures"],
        "evidence_types": ["siem_config"],
    }

CONTROLS["AU-8"] = {
    "summary": "Use internal system clocks to generate time stamps for audit records",
    "remediation_steps": [
        "Configure NTP synchronization on all systems",
        "Use authoritative time sources (NIST, GPS, or organizational time servers)",
        "Verify time synchronization accuracy within 1 second",
        "Monitor NTP sync status and alert on drift",
    ],
    "console_path": "Systems > NTP Configuration | EC2 > Amazon Time Sync Service",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-8 Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["AU-9"] = {
    "summary": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion",
    "remediation_steps": [
        "Configure S3 Object Lock or immutable storage for audit logs",
        "Restrict write access to audit log storage to logging service only",
        "Enable log file integrity validation (CloudTrail log file validation)",
        "Implement separate audit log account with cross-account logging",
    ],
    "console_path": "S3 > Audit Bucket > Object Lock | CloudTrail > Log File Validation",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-9 Assessment Procedures"],
    "evidence_types": ["s3_buckets", "cloudtrail_trails"],
}

for enh in range(1, 8):
    names = {
        1: "Hardware write-once media",
        2: "Store on separate physical systems",
        3: "Cryptographic protection of audit information",
        4: "Access by subset of privileged users",
        5: "Dual authorization for movement or deletion",
        6: "Read-only access",
        7: "Store on component with different OS",
    }
    steps_map = {
        1: [
            "Implement write-once storage for critical audit logs",
            "Configure WORM storage policies",
            "Verify write-once enforcement",
            "Test tamper resistance",
        ],
        2: [
            "Store audit logs on dedicated logging infrastructure",
            "Implement cross-account or cross-subscription logging",
            "Verify physical or logical separation of log storage",
            "Monitor log storage infrastructure independently",
        ],
        3: [
            "Enable encryption at rest for all audit logs",
            "Implement log signing for integrity verification",
            "Configure KMS key policies for audit log encryption",
            "Verify cryptographic protection regularly",
        ],
        4: [
            "Restrict audit log access to security team members only",
            "Implement IAM policies limiting audit log access",
            "Configure separate roles for audit log administration",
            "Review audit log access quarterly",
        ],
        5: [
            "Require dual authorization for audit log deletion or movement",
            "Implement two-person integrity for log management actions",
            "Log all audit log management operations",
            "Test dual authorization enforcement",
        ],
        6: [
            "Configure read-only access to audit records for reviewers",
            "Prevent modification of audit records after creation",
            "Implement append-only log storage",
            "Verify read-only enforcement",
        ],
        7: [
            "Store audit logs on systems with different operating system",
            "Implement cross-platform log storage for defense in depth",
            "Verify OS diversity in log storage infrastructure",
            "Document OS diversity configuration",
        ],
    }
    CONTROLS[f"AU-9({enh})"] = {
        "summary": names[enh],
        "remediation_steps": steps_map[enh],
        "console_path": "S3 > Audit Bucket > Protection Settings",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-9({enh}) Assessment Procedures"],
        "evidence_types": ["s3_buckets", "config_snapshots"],
    }

CONTROLS["AU-10"] = {
    "summary": "Provide non-repudiation of actions by associating actions to individuals",
    "remediation_steps": [
        "Implement individual accountability through unique user accounts",
        "Configure audit logging with user identity for all actions",
        "Enable digital signatures for critical transactions",
        "Prohibit shared account use for auditable actions",
    ],
    "console_path": "IAM > Users | CloudTrail > Event History",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-10 Assessment Procedures"],
    "evidence_types": ["cloudtrail_trails", "audit_logs"],
}

for enh in range(1, 6):
    names = {
        1: "Association of identities",
        2: "Validate binding of information producer identity",
        3: "Chain of custody",
        4: "Validate binding of information reviewer identity",
        5: "Digital signatures",
    }
    steps_list = {
        1: [
            "Bind user identities to audit records cryptographically",
            "Implement digital certificate-based authentication",
            "Verify identity binding in audit record integrity checks",
            "Test non-repudiation mechanisms",
        ],
        2: [
            "Validate information producer identity at creation",
            "Implement code signing for software artifacts",
            "Configure content attribution mechanisms",
            "Verify producer identity binding",
        ],
        3: [
            "Implement chain of custody tracking for evidence",
            "Configure hash-chaining for audit records",
            "Maintain cryptographic proof of custody transfers",
            "Verify chain of custody integrity",
        ],
        4: [
            "Bind reviewer identity to review actions",
            "Implement approval signatures in workflows",
            "Log reviewer identity for all review actions",
            "Verify reviewer identity binding",
        ],
        5: [
            "Implement digital signatures for non-repudiation",
            "Configure PKI for document and transaction signing",
            "Verify digital signature validity",
            "Manage signing certificates and keys",
        ],
    }
    CONTROLS[f"AU-10({enh})"] = {
        "summary": names[enh],
        "remediation_steps": steps_list[enh],
        "console_path": "Certificate Manager > Signing Certificates",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-10({enh}) Assessment Procedures"],
        "evidence_types": ["audit_logs", "config_snapshots"],
    }

CONTROLS["AU-11"] = {
    "summary": "Retain audit records for a defined period to support after-the-fact investigations",
    "remediation_steps": [
        "Configure audit log retention for minimum 1 year (90 days hot, remainder in archive)",
        "Implement S3 Glacier or Azure Cool Storage for long-term log retention",
        "Set up lifecycle policies for automatic log archival",
        "Verify retention compliance monthly",
    ],
    "console_path": "S3 > Lifecycle Policies | CloudWatch Logs > Retention",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-11 Assessment Procedures"],
    "evidence_types": ["s3_buckets", "config_snapshots"],
}

CONTROLS["AU-11(1)"] = {
    "summary": "Long-term retrieval capability for audit records",
    "remediation_steps": [
        "Ensure archived audit records can be retrieved within defined timeframe",
        "Test log retrieval from long-term storage quarterly",
        "Document retrieval procedures and expected timeframes",
        "Verify archived log integrity upon retrieval",
    ],
    "console_path": "S3 Glacier > Retrieval Configuration",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-11(1) Assessment Procedures"],
    "evidence_types": ["s3_buckets"],
}

CONTROLS["AU-12"] = {
    "summary": "Provide audit record generation capability for auditable events",
    "remediation_steps": [
        "Enable CloudTrail multi-region trail with management events",
        "Configure VPC Flow Logs on all VPCs",
        "Enable Azure Diagnostic Settings on all resources",
        "Enable GCP Cloud Audit Logs for admin and data access",
        "Verify audit record generation for all defined auditable events",
    ],
    "console_path": "CloudTrail > Trails > Create | VPC > Flow Logs | Azure Monitor > Diagnostic Settings",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-12 Assessment Procedures"],
    "evidence_types": ["cloudtrail_trails", "audit_logs", "activity_log"],
}

for enh, summ, steps in [
    (
        "1",
        "System-wide and time-correlated audit trail",
        [
            "Implement centralized logging with time-correlated audit trail",
            "Configure SIEM for system-wide event correlation",
            "Ensure consistent timestamps across all log sources",
            "Verify time correlation accuracy across systems",
        ],
    ),
    (
        "2",
        "Standardized formats for audit record content",
        [
            "Define standard audit record format (CEF, ECS, or OCSF)",
            "Configure log normalization in SIEM",
            "Implement format validation for incoming log sources",
            "Document standard format specification",
        ],
    ),
    (
        "3",
        "Changes by authorized individuals",
        [
            "Enable authorized individuals to change audit configuration",
            "Restrict audit configuration changes to security administrators",
            "Log all changes to audit configuration",
            "Review audit configuration changes weekly",
        ],
    ),
    (
        "4",
        "Query parameter audits of personally identifiable information",
        [
            "Audit database queries that access PII",
            "Configure query logging for PII-containing tables",
            "Alert on bulk PII access queries",
            "Review PII access audit logs weekly",
        ],
    ),
]:
    CONTROLS[f"AU-12({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "CloudTrail > Configuration | SIEM > Log Normalization",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-12({enh}) Assessment Procedures"],
        "evidence_types": ["cloudtrail_trails", "audit_logs"],
    }

CONTROLS["AU-13"] = {
    "summary": "Monitor open source information for evidence of unauthorized disclosure",
    "remediation_steps": [
        "Implement monitoring for organizational data on public repositories",
        "Configure GitHub secret scanning for organizational secrets",
        "Monitor dark web for leaked credentials",
        "Set up alerts for organizational data found in open sources",
    ],
    "console_path": "GitHub > Security > Secret Scanning | Dark Web Monitoring",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-13 Assessment Procedures"],
    "evidence_types": ["github_alerts", "dark_web_monitoring"],
}

CONTROLS["AU-14"] = {
    "summary": "Provide session audit capability",
    "remediation_steps": [
        "Implement session recording for privileged access",
        "Configure CyberArk PSM or equivalent session recorder",
        "Enable AWS Systems Manager Session Manager logging",
        "Store session recordings securely with tamper protection",
    ],
    "console_path": "CyberArk > PSM > Session Recordings | SSM > Session Manager",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-14 Assessment Procedures"],
    "evidence_types": ["session_recordings", "audit_logs"],
}

for enh, summ, steps in [
    (
        "1",
        "System start-up audit capture",
        [
            "Enable audit logging during system boot and initialization",
            "Configure boot-time event capture",
            "Verify audit subsystem starts before user-accessible services",
            "Test boot audit capture on system restart",
        ],
    ),
    (
        "2",
        "Capture and record content",
        [
            "Configure full session content capture for privileged access",
            "Enable keystroke and screen capture for administrative sessions",
            "Implement secure storage for captured session content",
            "Restrict access to session recordings",
        ],
    ),
    (
        "3",
        "Remote viewing and listening",
        [
            "Implement real-time session monitoring capability for security operations",
            "Configure live session viewing in PAM tool",
            "Enable session interruption capability for suspicious activity",
            "Document session monitoring procedures and authorization",
        ],
    ),
]:
    CONTROLS[f"AU-14({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "CyberArk > PSM | SSM > Session Manager",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: AU-14({enh}) Assessment Procedures"],
        "evidence_types": ["session_recordings"],
    }

CONTROLS["AU-15"] = {
    "summary": "Alternate audit logging capability (withdrawn - incorporated into AU-5(5))",
    "remediation_steps": [
        "This control has been withdrawn and incorporated into AU-5(5)",
        "Verify AU-5(5) alternate audit logging controls are implemented",
    ],
    "console_path": "See AU-5(5)",
    "recommended_reading": ["NIST SP 800-53 Rev 5: AU-15 Withdrawal Notice"],
    "evidence_types": ["policy_document"],
}

CONTROLS["AU-16"] = {
    "summary": "Cross-organizational audit logging",
    "remediation_steps": [
        "Define audit logging requirements for cross-organizational systems",
        "Implement shared audit logging infrastructure with partners",
        "Configure cross-account or cross-tenant log sharing",
        "Review cross-organizational audit agreements annually",
    ],
    "console_path": "CloudTrail > Organization Trail | Sentinel > Multi-Tenant",
    "recommended_reading": ["NIST SP 800-53A Rev 5: AU-16 Assessment Procedures"],
    "evidence_types": ["cloudtrail_trails", "config_snapshots"],
}

# ============================================================
# CA — Assessment, Authorization, and Monitoring
# ============================================================

CONTROLS["CA-1"] = {
    "summary": "Develop, document, and disseminate assessment, authorization, and monitoring policy",
    "remediation_steps": [
        "Draft security assessment and authorization policy",
        "Define authorization boundaries and assessment requirements",
        "Establish continuous monitoring strategy",
        "Review and update policy annually",
    ],
    "console_path": "Confluence > SEC Space > Assessment Policy",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: CA-1 Assessment Procedures",
        "NIST SP 800-37: RMF Guide",
    ],
    "evidence_types": ["policy_document", "policy_review_date"],
}

CONTROLS["CA-2"] = {
    "summary": "Develop a security and privacy assessment plan and assess controls",
    "remediation_steps": [
        "Develop security assessment plan with scope, schedule, and assessors",
        "Conduct annual security assessments of all controls",
        "Document assessment results and findings",
        "Track remediation of assessment findings",
    ],
    "console_path": "GRC Platform > Assessments > Plans",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: CA-2 Assessment Procedures",
        "NIST SP 800-53A: Assessment Guide",
    ],
    "evidence_types": ["assessment_reports", "policy_document"],
}

for enh, summ, steps in [
    (
        "1",
        "Independent assessors",
        [
            "Engage independent assessors for security assessments",
            "Verify assessor independence and qualifications",
            "Document assessor selection criteria and rationale",
            "Review assessor performance after each assessment",
        ],
    ),
    (
        "2",
        "Specialized assessments",
        [
            "Conduct specialized assessments (penetration testing, code review)",
            "Define specialized assessment requirements by system type",
            "Schedule specialized assessments based on risk",
            "Integrate specialized assessment findings into overall results",
        ],
    ),
    (
        "3",
        "Leveraging results from external organizations",
        [
            "Accept and leverage assessment results from FedRAMP, SOC 2, or ISO audits",
            "Map external assessment results to organizational control requirements",
            "Document which controls are covered by external assessments",
            "Supplement external results for gaps in coverage",
        ],
    ),
]:
    CONTROLS[f"CA-2({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "GRC Platform > Assessments",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CA-2({enh}) Assessment Procedures"],
        "evidence_types": ["assessment_reports"],
    }

CONTROLS["CA-3"] = {
    "summary": "Approve and manage information exchange through system connections",
    "remediation_steps": [
        "Document all system interconnections with ISAs/MOUs",
        "Review and authorize each interconnection",
        "Implement security controls at interconnection points",
        "Review interconnection agreements annually",
    ],
    "console_path": "Network > Interconnections | VPC Peering > Agreements",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CA-3 Assessment Procedures"],
    "evidence_types": ["policy_document", "config_snapshots"],
}

for enh in range(1, 8):
    names = {
        1: "Unclassified national security system connections",
        2: "Classified national security system connections",
        3: "Unclassified non-national security system connections",
        4: "Connections to public networks",
        5: "Restrictions on external system connections",
        6: "Transfer authorizations",
        7: "Transitive information exchanges",
    }
    CONTROLS[f"CA-3({enh})"] = {
        "summary": names[enh],
        "remediation_steps": [
            f"Document and authorize {names[enh].lower()}",
            "Implement security controls appropriate to connection classification",
            "Review connection authorization annually",
            "Monitor connection activity for anomalies",
        ],
        "console_path": "Network > System Interconnections",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CA-3({enh}) Assessment Procedures"],
        "evidence_types": ["policy_document", "config_snapshots"],
    }

CONTROLS["CA-4"] = {
    "summary": "Security certification (withdrawn - incorporated into CA-2)",
    "remediation_steps": [
        "This control has been withdrawn and incorporated into CA-2",
        "Verify CA-2 assessment controls are implemented",
    ],
    "console_path": "See CA-2",
    "recommended_reading": ["NIST SP 800-53 Rev 5: CA-4 Withdrawal Notice"],
    "evidence_types": ["policy_document"],
}

CONTROLS["CA-5"] = {
    "summary": "Develop a plan of action and milestones (POA&M) for the system",
    "remediation_steps": [
        "Create POA&M for all identified weaknesses and deficiencies",
        "Assign remediation owners and target dates for each finding",
        "Track POA&M progress monthly",
        "Close POA&M items only after remediation verification",
    ],
    "console_path": "GRC Platform > POA&M > Active Items",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CA-5 Assessment Procedures"],
    "evidence_types": ["poam_document"],
}

CONTROLS["CA-5(1)"] = {
    "summary": "Automation support for accuracy and currency of POA&M",
    "remediation_steps": [
        "Implement automated POA&M tracking in GRC platform",
        "Configure automated status updates from remediation tools",
        "Generate automated POA&M reports for management review",
        "Verify POA&M accuracy through automated checks",
    ],
    "console_path": "GRC Platform > POA&M > Automation",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CA-5(1) Assessment Procedures"],
    "evidence_types": ["poam_document"],
}

CONTROLS["CA-6"] = {
    "summary": "Authorize system operation based on acceptable risk determination",
    "remediation_steps": [
        "Prepare authorization package (SSP, SAR, POA&M)",
        "Submit authorization package to authorizing official",
        "Obtain signed ATO before system operation",
        "Reauthorize on significant changes or at least every 3 years",
    ],
    "console_path": "GRC Platform > Authorizations > ATO Package",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: CA-6 Assessment Procedures",
        "NIST SP 800-37: RMF Guide",
    ],
    "evidence_types": ["ato_document", "assessment_reports"],
}

CONTROLS["CA-7"] = {
    "summary": "Develop a continuous monitoring strategy and program",
    "remediation_steps": [
        "Implement continuous monitoring using AWS Config, Security Hub, or Defender",
        "Define monitoring frequency per control category",
        "Configure automated compliance checking",
        "Generate continuous monitoring reports monthly",
    ],
    "console_path": "AWS Config > Conformance Packs | Security Hub > Standards",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: CA-7 Assessment Procedures",
        "NIST SP 800-137: ISCM Guide",
    ],
    "evidence_types": ["config_rules", "security_hub_findings"],
}

for enh, summ, steps in [
    (
        "1",
        "Independent assessment",
        [
            "Engage independent assessors for continuous monitoring validation",
            "Conduct independent assessment of monitoring effectiveness",
            "Document independent assessment findings",
            "Address independent assessment recommendations",
        ],
    ),
    (
        "2",
        "Types of assessments",
        [
            "Define assessment types for continuous monitoring (automated scans, manual reviews)",
            "Schedule different assessment types at appropriate frequencies",
            "Integrate multiple assessment types into monitoring program",
            "Report on assessment type coverage",
        ],
    ),
    (
        "3",
        "Trend analysis",
        [
            "Implement trend analysis on monitoring data",
            "Track control effectiveness metrics over time",
            "Alert on negative compliance trends",
            "Report compliance trends to management monthly",
        ],
    ),
    (
        "4",
        "Risk monitoring",
        [
            "Implement risk-based monitoring adjustments",
            "Increase monitoring frequency for high-risk controls",
            "Integrate threat intelligence into monitoring priorities",
            "Report risk monitoring results to authorizing official",
        ],
    ),
    (
        "5",
        "Consistency analysis",
        [
            "Analyze monitoring results for consistency across systems",
            "Identify and investigate inconsistent compliance results",
            "Normalize monitoring data for cross-system comparison",
            "Report consistency analysis findings",
        ],
    ),
    (
        "6",
        "Automation support for monitoring",
        [
            "Implement automated compliance monitoring tools",
            "Configure automated evidence collection",
            "Enable automated alerting on compliance deviations",
            "Verify automated monitoring coverage",
        ],
    ),
]:
    CONTROLS[f"CA-7({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "GRC Platform > Continuous Monitoring",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CA-7({enh}) Assessment Procedures"],
        "evidence_types": ["config_rules", "assessment_reports"],
    }

CONTROLS["CA-8"] = {
    "summary": "Conduct penetration testing on systems",
    "remediation_steps": [
        "Schedule annual penetration testing of organizational systems",
        "Define rules of engagement and scope for penetration tests",
        "Engage qualified penetration testing team",
        "Track and remediate penetration testing findings",
    ],
    "console_path": "GRC Platform > Assessments > Penetration Tests",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: CA-8 Assessment Procedures",
        "NIST SP 800-115: Technical Guide to Information Security Testing",
    ],
    "evidence_types": ["pentest_reports"],
}

for enh, summ, steps in [
    (
        "1",
        "Independent penetration testing agent",
        [
            "Engage independent third-party penetration testing firm",
            "Verify tester independence and qualifications",
            "Rotate testing firms periodically",
            "Review and act on independent test results",
        ],
    ),
    (
        "2",
        "Red team exercises",
        [
            "Conduct annual red team exercises",
            "Define red team scope and rules of engagement",
            "Test detection and response capabilities",
            "Document lessons learned from red team exercises",
        ],
    ),
    (
        "3",
        "Facility penetration testing",
        [
            "Include physical security in penetration testing scope",
            "Test physical access controls and badge reader systems",
            "Assess social engineering at facility level",
            "Document physical security test findings",
        ],
    ),
]:
    CONTROLS[f"CA-8({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "GRC Platform > Assessments > Penetration Tests",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CA-8({enh}) Assessment Procedures"],
        "evidence_types": ["pentest_reports"],
    }

CONTROLS["CA-9"] = {
    "summary": "Authorize internal system connections",
    "remediation_steps": [
        "Document all internal system connections",
        "Review and authorize each internal connection",
        "Implement security controls on internal connections",
        "Review internal connections annually",
    ],
    "console_path": "VPC > Peering Connections | Network > Internal Connections",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CA-9 Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

CONTROLS["CA-9(1)"] = {
    "summary": "Compliance checks for internal connections",
    "remediation_steps": [
        "Implement compliance verification for internal connections",
        "Configure automated security posture checks before allowing connections",
        "Monitor internal connection compliance continuously",
        "Alert on non-compliant internal connections",
    ],
    "console_path": "Network > Connection Compliance",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CA-9(1) Assessment Procedures"],
    "evidence_types": ["config_snapshots"],
}

# ============================================================
# CM — Configuration Management
# ============================================================

CONTROLS["CM-1"] = {
    "summary": "Develop, document, and disseminate configuration management policy and procedures",
    "remediation_steps": [
        "Draft configuration management policy covering all systems",
        "Define configuration baselines and change management requirements",
        "Establish configuration review and update procedures",
        "Distribute policy to all organizational personnel",
    ],
    "console_path": "Confluence > SEC Space > Configuration Management Policy",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-1 Assessment Procedures"],
    "evidence_types": ["policy_document", "policy_review_date"],
}

CONTROLS["CM-2"] = {
    "summary": "Develop, document, and maintain baseline configurations for systems",
    "remediation_steps": [
        "Enable AWS Config recorder to capture configuration baselines",
        "Define and document approved baseline configurations",
        "Implement CIS hardened AMIs or VM images as baselines",
        "Monitor configuration drift from baselines using AWS Config rules",
    ],
    "console_path": "AWS Config > Configuration Recorder | Systems Manager > Inventory",
    "recommended_reading": [
        "NIST SP 800-53A Rev 5: CM-2 Assessment Procedures",
        "CIS Benchmarks for AWS/Azure/GCP",
    ],
    "evidence_types": ["config_rules", "config_snapshots"],
}

for enh, summ, steps in [
    (
        "1",
        "Reviews and updates to baseline configurations",
        [
            "Review baseline configurations annually and after significant changes",
            "Update baselines to address new vulnerabilities and threats",
            "Document baseline changes and approval",
            "Verify systems comply with updated baselines",
        ],
    ),
    (
        "2",
        "Automation support for accuracy and currency",
        [
            "Implement automated baseline compliance checking",
            "Configure AWS Config rules for baseline drift detection",
            "Enable automated remediation for baseline deviations",
            "Generate baseline compliance reports",
        ],
    ),
    (
        "3",
        "Retention of previous configurations",
        [
            "Retain previous baseline configurations for rollback capability",
            "Configure version control for infrastructure configurations",
            "Maintain configuration history for audit purposes",
            "Define retention period for previous configurations",
        ],
    ),
    (
        "4",
        "Unauthorized software (withdrawn)",
        [
            "This enhancement has been withdrawn and incorporated into CM-7(4) and CM-7(5)",
            "Verify CM-7 software restriction controls are implemented",
        ],
    ),
    (
        "5",
        "Authorized software (withdrawn)",
        [
            "This enhancement has been withdrawn and incorporated into CM-7(4) and CM-7(5)",
            "Verify CM-7 software restriction controls are implemented",
        ],
    ),
    (
        "6",
        "Development and test environments",
        [
            "Maintain separate baseline configurations for dev, test, and production",
            "Ensure development baselines do not weaken production security",
            "Document differences between environment baselines",
            "Review environment baseline differences quarterly",
        ],
    ),
    (
        "7",
        "Configure systems and components for high-risk areas",
        [
            "Define hardened configurations for systems in high-risk areas",
            "Apply additional security controls for high-risk deployments",
            "Verify hardened configurations before deployment to high-risk areas",
            "Monitor high-risk area configurations more frequently",
        ],
    ),
]:
    CONTROLS[f"CM-2({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "AWS Config > Rules | Configuration Management",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CM-2({enh}) Assessment Procedures"],
        "evidence_types": ["config_rules", "config_snapshots"],
    }

CONTROLS["CM-3"] = {
    "summary": "Determine and manage types of changes to the system that are configuration-controlled",
    "remediation_steps": [
        "Implement change management process with approval workflows",
        "Configure Jira or ServiceNow for change request tracking",
        "Require documented approval before implementing changes",
        "Maintain change log for all configuration changes",
    ],
    "console_path": "Jira > Change Management Board | ServiceNow > Change Requests",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-3 Assessment Procedures"],
    "evidence_types": ["jira_issues", "change_records"],
}

for enh, summ, steps in [
    (
        "1",
        "Automated documentation and notification",
        [
            "Implement automated change documentation in CI/CD pipeline",
            "Configure automated notifications for configuration changes",
            "Enable git-based change tracking for all infrastructure",
            "Verify automated documentation completeness",
        ],
    ),
    (
        "2",
        "Testing and validation of changes",
        [
            "Require testing before production deployment of changes",
            "Implement CI/CD pipeline with automated testing gates",
            "Configure staging environment for change validation",
            "Document test results for each change",
        ],
    ),
    (
        "3",
        "Automated change implementation",
        [
            "Implement infrastructure as code for automated change deployment",
            "Use Terraform or CloudFormation for infrastructure changes",
            "Configure automated rollback on failed deployments",
            "Verify automated changes match approved change requests",
        ],
    ),
    (
        "4",
        "Security and privacy representatives",
        [
            "Include security team in change advisory board",
            "Require security review for changes affecting security controls",
            "Document security impact assessment for each change",
            "Track security review completion for changes",
        ],
    ),
    (
        "5",
        "Automated security response to changes",
        [
            "Implement automated security scanning after configuration changes",
            "Configure triggered security assessments on changes",
            "Enable automated rollback on security policy violations",
            "Alert on changes that degrade security posture",
        ],
    ),
    (
        "6",
        "Cryptography management",
        [
            "Manage cryptographic changes through change management process",
            "Document cryptographic configuration changes",
            "Require cryptographic review for algorithm or key changes",
            "Track cryptographic configuration baseline",
        ],
    ),
    (
        "7",
        "Review system changes",
        [
            "Review system changes within defined timeframe after implementation",
            "Verify changes match approved change requests",
            "Assess impact of implemented changes",
            "Document post-implementation review results",
        ],
    ),
    (
        "8",
        "Prevent or restrict configuration changes",
        [
            "Implement configuration lockdown for production systems",
            "Use immutable infrastructure where possible",
            "Restrict configuration change access to authorized personnel",
            "Monitor for unauthorized configuration changes",
        ],
    ),
]:
    CONTROLS[f"CM-3({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "Jira > Change Management | CI/CD Pipeline",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CM-3({enh}) Assessment Procedures"],
        "evidence_types": ["change_records", "config_snapshots"],
    }

CONTROLS["CM-4"] = {
    "summary": "Analyze changes to the system to determine potential security and privacy impacts",
    "remediation_steps": [
        "Conduct security impact analysis before implementing changes",
        "Require change request to include security impact assessment",
        "Implement automated security scanning in CI/CD pipeline",
        "Document security impact analysis results for each change",
    ],
    "console_path": "Jira > Change Request > Security Impact | CI/CD > Security Gates",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-4 Assessment Procedures"],
    "evidence_types": ["change_records", "security_scan_results"],
}

for enh, summ, steps in [
    (
        "1",
        "Separate test environments",
        [
            "Maintain separate test environments for change validation",
            "Ensure test environments mirror production configuration",
            "Conduct security testing in isolated environments",
            "Verify test environment isolation from production",
        ],
    ),
    (
        "2",
        "Verification of controls",
        [
            "Verify security controls function correctly after changes",
            "Implement automated control verification testing",
            "Document control verification results",
            "Re-test controls affected by changes",
        ],
    ),
]:
    CONTROLS[f"CM-4({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "CI/CD > Test Environments | Security Testing",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CM-4({enh}) Assessment Procedures"],
        "evidence_types": ["change_records", "security_scan_results"],
    }

CONTROLS["CM-5"] = {
    "summary": "Define, document, approve, and enforce physical and logical access restrictions on system changes",
    "remediation_steps": [
        "Restrict change access to authorized administrators",
        "Implement code review requirements before merging",
        "Configure branch protection rules in source control",
        "Log all system change activities",
    ],
    "console_path": "GitHub > Branch Protection | IAM > Change Access Roles",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-5 Assessment Procedures"],
    "evidence_types": ["github_settings", "iam_policies"],
}

for enh in range(1, 8):
    names = {
        1: "Automated access enforcement and audit records",
        2: "Review system changes",
        3: "Signed components",
        4: "Dual authorization",
        5: "Privilege limitation for production and operation",
        6: "Limit library privileges",
        7: "Automatic implementation of security safeguards",
    }
    steps_map = {
        1: [
            "Implement automated access enforcement for change management",
            "Configure audit logging for all change activities",
            "Generate automated reports on change access",
            "Verify access enforcement effectiveness",
        ],
        2: [
            "Conduct post-implementation review of system changes",
            "Verify changes match approved specifications",
            "Document review findings",
            "Track unresolved review findings",
        ],
        3: [
            "Require code signing for all deployed components",
            "Implement artifact signing in CI/CD pipeline",
            "Verify signatures before deployment",
            "Manage signing keys securely",
        ],
        4: [
            "Require dual authorization for production changes",
            "Implement two-person review in CI/CD pipeline",
            "Log dual authorization for audit",
            "Test dual authorization enforcement",
        ],
        5: [
            "Restrict production access to deployment pipelines",
            "Prohibit direct production access except for emergency",
            "Implement break-glass procedures for emergency production access",
            "Audit production access monthly",
        ],
        6: [
            "Restrict access to software libraries and repositories",
            "Implement library access controls based on role",
            "Monitor library access and changes",
            "Review library privileges quarterly",
        ],
        7: [
            "Implement automated security controls triggered by configuration changes",
            "Configure automated rollback on security violations",
            "Enable automated compliance scanning after changes",
            "Verify automatic safeguard effectiveness",
        ],
    }
    CONTROLS[f"CM-5({enh})"] = {
        "summary": names[enh],
        "remediation_steps": steps_map[enh],
        "console_path": "CI/CD > Pipeline Security | GitHub > Branch Protection",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CM-5({enh}) Assessment Procedures"],
        "evidence_types": ["change_records", "config_snapshots"],
    }

CONTROLS["CM-6"] = {
    "summary": "Establish and enforce security configuration settings for IT products",
    "remediation_steps": [
        "Apply CIS Benchmark configurations to all systems",
        "Enable AWS Config rules to monitor configuration compliance",
        "Configure Azure Policy for configuration enforcement",
        "Review and update configuration settings quarterly",
    ],
    "console_path": "AWS Config > Conformance Packs > CIS | Azure Policy > Compliance",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-6 Assessment Procedures", "CIS Benchmarks"],
    "evidence_types": ["config_rules", "config_snapshots"],
}

for enh, summ, steps in [
    (
        "1",
        "Automated management and enforcement",
        [
            "Implement automated configuration management tools",
            "Configure auto-remediation for configuration drift",
            "Enable AWS Config auto-remediation rules",
            "Verify automated enforcement effectiveness",
        ],
    ),
    (
        "2",
        "Respond to unauthorized changes",
        [
            "Configure alerts for unauthorized configuration changes",
            "Implement automated response to unauthorized changes",
            "Enable automatic rollback for unauthorized modifications",
            "Review unauthorized change incidents weekly",
        ],
    ),
    (
        "3",
        "Unauthorized change detection",
        [
            "Implement file integrity monitoring (FIM) on critical systems",
            "Configure AWS Config change detection rules",
            "Alert on unauthorized configuration modifications",
            "Investigate unauthorized changes within 24 hours",
        ],
    ),
    (
        "4",
        "Conformance demonstration",
        [
            "Generate configuration compliance reports",
            "Demonstrate conformance through automated scanning",
            "Maintain configuration compliance dashboards",
            "Report conformance status to management monthly",
        ],
    ),
]:
    CONTROLS[f"CM-6({enh})"] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": "AWS Config > Rules | Azure Policy > Remediation",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CM-6({enh}) Assessment Procedures"],
        "evidence_types": ["config_rules", "config_snapshots"],
    }

CONTROLS["CM-7"] = {
    "summary": "Configure the system to provide only mission-essential capabilities and restrict the use of non-essential functions",
    "remediation_steps": [
        "Disable unnecessary services, ports, and protocols",
        "Remove unused software packages from production systems",
        "Configure minimal base images for containers and VMs",
        "Review enabled services and functions quarterly",
    ],
    "console_path": "EC2 > Security Groups > Port Review | Systems > Service Configuration",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-7 Assessment Procedures"],
    "evidence_types": ["ec2_security_groups", "config_snapshots"],
}

for enh in range(1, 10):
    names = {
        1: "Periodic review",
        2: "Prevent program execution",
        3: "Registration compliance",
        4: "Unauthorized software or deny-all/allow-by-exception",
        5: "Authorized software or allow-all/deny-by-exception",
        6: "Confined environments with limited privileges",
        7: "Code execution in protected environments",
        8: "Binary or machine executable code",
        9: "Prohibiting use of unauthorized hardware",
    }
    steps_map = {
        1: [
            "Conduct periodic review of enabled system capabilities",
            "Disable functions no longer needed",
            "Document review results and actions taken",
            "Review at least annually",
        ],
        2: [
            "Implement application whitelisting to prevent unauthorized execution",
            "Configure AppLocker or equivalent program execution controls",
            "Block execution of unauthorized scripts and binaries",
            "Monitor blocked execution attempts",
        ],
        3: [
            "Register software in organizational software inventory",
            "Verify software registration compliance",
            "Remove unregistered software",
            "Update registration requirements annually",
        ],
        4: [
            "Implement deny-all application whitelisting policy",
            "Configure explicit allow list for authorized software",
            "Block installation of unauthorized software",
            "Review authorized software list quarterly",
        ],
        5: [
            "Maintain deny list of prohibited software",
            "Configure automated detection and removal of prohibited software",
            "Alert on prohibited software installation attempts",
            "Update deny list based on threat intelligence",
        ],
        6: [
            "Execute software in sandboxed or confined environments",
            "Configure container security policies with restricted capabilities",
            "Implement mandatory access control for application processes",
            "Verify confinement effectiveness through testing",
        ],
        7: [
            "Execute untrusted code in protected environments only",
            "Configure separate execution environments for untrusted code",
            "Implement code isolation mechanisms",
            "Monitor protected environment activity",
        ],
        8: [
            "Restrict execution of binary or machine-executable code",
            "Require approval for binary code execution",
            "Implement code signing verification",
            "Block unsigned binary execution",
        ],
        9: [
            "Maintain inventory of authorized hardware",
            "Implement network access control for hardware",
            "Block unauthorized hardware connections",
            "Detect and alert on unauthorized hardware",
        ],
    }
    CONTROLS[f"CM-7({enh})"] = {
        "summary": names[enh],
        "remediation_steps": steps_map[enh],
        "console_path": "Systems > Software Inventory | Endpoint > Application Control",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CM-7({enh}) Assessment Procedures"],
        "evidence_types": ["config_snapshots", "software_inventory"],
    }

CONTROLS["CM-8"] = {
    "summary": "Develop and maintain an inventory of system components",
    "remediation_steps": [
        "Implement automated asset discovery and inventory",
        "Configure AWS Config, Azure Resource Graph, or GCP Asset Inventory",
        "Maintain CMDB with all system components",
        "Reconcile automated inventory with CMDB quarterly",
    ],
    "console_path": "AWS Config > Resources | Azure Resource Graph | ServiceNow > CMDB",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-8 Assessment Procedures"],
    "evidence_types": ["asset_inventory", "config_snapshots"],
}

for enh in range(1, 10):
    names = {
        1: "Updates during installation and removal",
        2: "Automated maintenance",
        3: "Automated unauthorized component detection",
        4: "Accountability information",
        5: "No duplicate accounting of components",
        6: "Assessed configurations and approved deviations",
        7: "Centralized repository",
        8: "Automated location tracking",
        9: "Assignment of components to systems",
    }
    steps_map = {
        1: [
            "Update inventory when installing or removing components",
            "Configure automated inventory updates on deployment",
            "Verify inventory accuracy after changes",
            "Alert on inventory discrepancies",
        ],
        2: [
            "Implement automated inventory maintenance through discovery tools",
            "Configure scheduled inventory scans",
            "Enable auto-update of inventory on resource changes",
            "Verify automated maintenance completeness",
        ],
        3: [
            "Configure automated detection of unauthorized components",
            "Alert on components not in approved inventory",
            "Implement network-based asset discovery",
            "Investigate unauthorized components within 24 hours",
        ],
        4: [
            "Include accountability information in inventory (owner, custodian, location)",
            "Assign ownership to all inventory items",
            "Update accountability information on personnel changes",
            "Review accountability assignments quarterly",
        ],
        5: [
            "Implement unique identifiers for all components",
            "Prevent duplicate entries in inventory",
            "Reconcile inventory across data sources",
            "Verify unique identification accuracy",
        ],
        6: [
            "Document assessed configurations for inventory items",
            "Track approved configuration deviations",
            "Review deviations and re-assess periodically",
            "Ensure baseline compliance for all components",
        ],
        7: [
            "Maintain centralized inventory repository",
            "Configure all discovery tools to feed central CMDB",
            "Provide role-based access to inventory data",
            "Backup inventory data regularly",
        ],
        8: [
            "Implement automated tracking of component locations",
            "Configure cloud provider resource tagging for location",
            "Track physical asset locations via asset management",
            "Verify location accuracy quarterly",
        ],
        9: [
            "Map components to system boundaries",
            "Ensure each component is assigned to exactly one system",
            "Update assignments on system boundary changes",
            "Verify assignments during authorization",
        ],
    }
    CONTROLS[f"CM-8({enh})"] = {
        "summary": names[enh],
        "remediation_steps": steps_map[enh],
        "console_path": "CMDB > Asset Inventory | AWS Config > Resources",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: CM-8({enh}) Assessment Procedures"],
        "evidence_types": ["asset_inventory"],
    }

CONTROLS["CM-9"] = {
    "summary": "Develop, document, and implement a configuration management plan",
    "remediation_steps": [
        "Document configuration management plan covering all system components",
        "Define configuration item identification and naming conventions",
        "Establish configuration control board procedures",
        "Review and update configuration management plan annually",
    ],
    "console_path": "Confluence > SEC Space > Configuration Management Plan",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-9 Assessment Procedures"],
    "evidence_types": ["policy_document"],
}

CONTROLS["CM-9(1)"] = {
    "summary": "Assignment of responsibility for configuration management",
    "remediation_steps": [
        "Assign configuration management responsibility to specific roles",
        "Document CM responsibilities in job descriptions",
        "Ensure CM roles have adequate authority and resources",
        "Review CM role assignments annually",
    ],
    "console_path": "Confluence > SEC Space > CM Roles and Responsibilities",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-9(1) Assessment Procedures"],
    "evidence_types": ["policy_document"],
}

CONTROLS["CM-10"] = {
    "summary": "Comply with software usage restrictions and licensing requirements",
    "remediation_steps": [
        "Maintain software license inventory and compliance tracking",
        "Implement software metering and usage monitoring",
        "Configure license compliance scanning tools",
        "Review software license compliance quarterly",
    ],
    "console_path": "ServiceNow > Software Asset Management | License Manager",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-10 Assessment Procedures"],
    "evidence_types": ["software_inventory", "license_records"],
}

CONTROLS["CM-10(1)"] = {
    "summary": "Open-source software usage",
    "remediation_steps": [
        "Maintain inventory of open-source software in use",
        "Review open-source licenses for compliance obligations",
        "Configure SCA tools for open-source component tracking",
        "Monitor open-source components for vulnerabilities",
    ],
    "console_path": "Snyk > Open Source > Dependencies | SBOM",
    "recommended_reading": ["NIST SP 800-53A Rev 5: CM-10(1) Assessment Procedures"],
    "evidence_types": ["software_inventory", "sbom"],
}

for ctrl in ["CM-11", "CM-12", "CM-13", "CM-14"]:
    base_num = ctrl.split("-")[1]
    names = {
        "11": "User-installed software",
        "12": "Information location",
        "13": "Data action mapping",
        "14": "Signed components",
    }
    steps_map = {
        "11": [
            "Define policy for user-installed software",
            "Configure application control to restrict user installs",
            "Monitor for unauthorized user software installations",
            "Review user-installed software policy annually",
        ],
        "12": [
            "Document locations of sensitive information across systems",
            "Implement automated data discovery and classification",
            "Maintain data flow maps for all sensitive information",
            "Update information location records on system changes",
        ],
        "13": [
            "Map data actions (collection, storage, sharing, processing) for PII",
            "Document data action purposes and legal bases",
            "Implement data action tracking in privacy management tool",
            "Review data action mappings annually",
        ],
        "14": [
            "Implement component signing and verification",
            "Require signed components in deployment pipeline",
            "Verify component signatures before installation",
            "Manage signing infrastructure securely",
        ],
    }
    CONTROLS[ctrl] = {
        "summary": names[base_num],
        "remediation_steps": steps_map[base_num],
        "console_path": "Configuration Management > " + names[base_num],
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl} Assessment Procedures"],
        "evidence_types": ["config_snapshots", "policy_document"],
    }

# CM enhancement stubs
for ctrl_enh in ["CM-11(1)", "CM-11(2)", "CM-11(3)", "CM-12(1)", "CM-14(1)"]:
    base = ctrl_enh.split("(")[0]
    enh_num = ctrl_enh.split("(")[1].rstrip(")")
    CONTROLS[ctrl_enh] = {
        "summary": f"Enhancement {enh_num} for {base}",
        "remediation_steps": [
            f"Implement additional controls for {base} enhancement {enh_num}",
            "Configure automated enforcement where applicable",
            "Verify enhancement effectiveness through testing",
            "Document implementation details",
        ],
        "console_path": f"Configuration Management > {base}",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_enh} Assessment Procedures"],
        "evidence_types": ["config_snapshots"],
    }

# ============================================================
# Now generate remaining families with pattern-based generation
# for families not yet explicitly defined
# ============================================================

# CP — Contingency Planning
CP_BASE = {
    "CP-1": (
        "Develop, document, and disseminate contingency planning policy and procedures",
        [
            "Draft contingency planning policy",
            "Define roles and responsibilities for contingency operations",
            "Establish contingency plan review cycle (at least annually)",
            "Distribute policy to all organizational personnel",
        ],
        "Confluence > SEC Space > Contingency Planning Policy",
        ["policy_document", "policy_review_date"],
    ),
    "CP-2": (
        "Develop a contingency plan for the system",
        [
            "Develop system contingency plan with recovery objectives (RPO/RTO)",
            "Identify essential missions and business functions",
            "Define recovery strategies and procedures",
            "Distribute plan to key personnel",
        ],
        "Confluence > SEC Space > Contingency Plan",
        ["policy_document", "contingency_plan"],
    ),
    "CP-3": (
        "Provide contingency training to system users",
        [
            "Conduct initial contingency training for new personnel",
            "Provide annual contingency training refresher",
            "Include role-specific contingency responsibilities",
            "Document training completion",
        ],
        "KnowBe4 > Training > Contingency Modules",
        ["training_records"],
    ),
    "CP-4": (
        "Test the contingency plan to determine effectiveness",
        [
            "Conduct annual contingency plan testing",
            "Include tabletop and functional exercises",
            "Document test results and lessons learned",
            "Update contingency plan based on test findings",
        ],
        "GRC Platform > Contingency Tests",
        ["test_reports"],
    ),
    "CP-5": (
        "Contingency plan update (withdrawn - incorporated into CP-2)",
        [
            "This control has been withdrawn and incorporated into CP-2",
            "Verify CP-2 contingency planning controls are implemented",
        ],
        "See CP-2",
        ["policy_document"],
    ),
    "CP-6": (
        "Establish an alternate storage site",
        [
            "Identify and establish alternate storage site",
            "Configure geographic separation for alternate storage",
            "Implement encryption for data at alternate site",
            "Test data retrieval from alternate site annually",
        ],
        "AWS > S3 Cross-Region Replication | Azure > GRS",
        ["config_snapshots"],
    ),
    "CP-7": (
        "Establish an alternate processing site",
        [
            "Identify and establish alternate processing site",
            "Configure multi-region or multi-zone deployment",
            "Verify alternate site can support essential operations",
            "Test failover to alternate processing site annually",
        ],
        "AWS > Multi-Region | Azure > Paired Regions",
        ["config_snapshots"],
    ),
    "CP-8": (
        "Establish alternate telecommunications services",
        [
            "Identify alternate telecommunications providers",
            "Configure redundant network connectivity",
            "Test alternate telecommunications paths",
            "Document telecommunications recovery procedures",
        ],
        "Network > Redundant Connectivity",
        ["config_snapshots"],
    ),
    "CP-9": (
        "Conduct system backups",
        [
            "Configure automated backups for all critical systems",
            "Implement backup encryption at rest",
            "Verify backup integrity through regular restore tests",
            "Monitor backup job success and alert on failures",
        ],
        "AWS Backup > Plans | Azure Backup > Vaults",
        ["backup_reports", "config_snapshots"],
    ),
    "CP-10": (
        "Provide for system recovery and reconstitution",
        [
            "Document system recovery procedures",
            "Implement automated recovery mechanisms",
            "Test system recovery annually",
            "Verify recovery meets defined RPO and RTO",
        ],
        "AWS > Disaster Recovery | Azure > Site Recovery",
        ["backup_reports", "test_reports"],
    ),
    "CP-11": (
        "Provide alternate communications protocols",
        [
            "Identify alternate communications protocols",
            "Configure failover communications",
            "Test alternate protocol activation",
            "Document communications recovery procedures",
        ],
        "Network > Alternate Protocols",
        ["config_snapshots"],
    ),
    "CP-12": (
        "Safe mode operation",
        [
            "Define safe mode operating conditions",
            "Implement safe mode activation procedures",
            "Test safe mode functionality",
            "Document safe mode limitations and capabilities",
        ],
        "Systems > Safe Mode Configuration",
        ["config_snapshots"],
    ),
    "CP-13": (
        "Alternate security mechanisms",
        [
            "Identify alternate security mechanisms for primary failure",
            "Document failover security procedures",
            "Test alternate security mechanism activation",
            "Verify alternate mechanisms provide adequate protection",
        ],
        "Security > Failover Mechanisms",
        ["config_snapshots"],
    ),
}

for ctrl_id, (summ, steps, cp, evid) in CP_BASE.items():
    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": evid,
    }

# CP enhancements - generate all
CP_ENH = {}
# CP-2 enhancements
for i in range(1, 9):
    names = {
        1: "Coordinate with related plans",
        2: "Capacity planning",
        3: "Resume mission functions",
        4: "Resume all mission functions",
        5: "Continue mission functions",
        6: "Alternate processing and storage site",
        7: "Coordinate with external service providers",
        8: "Identify critical assets",
    }
    CP_ENH[f"CP-2({i})"] = (names[i], "Contingency Planning > CP-2 Enhancements")

# CP-3 enhancements
CP_ENH["CP-3(1)"] = ("Simulated events in contingency training", "Contingency Planning > Training")
CP_ENH["CP-3(2)"] = ("Mechanisms used in contingency training", "Contingency Planning > Training")

# CP-4 enhancements
for i in range(1, 6):
    names = {
        1: "Coordinate with related plans testing",
        2: "Alternate processing site testing",
        3: "Automated testing",
        4: "Full recovery and reconstitution testing",
        5: "Self-challenge testing",
    }
    CP_ENH[f"CP-4({i})"] = (names[i], "Contingency Planning > Testing")

# CP-6 enhancements
for i in range(1, 4):
    names = {
        1: "Separation from primary site",
        2: "Recovery time and point objectives",
        3: "Accessibility",
    }
    CP_ENH[f"CP-6({i})"] = (names[i], "Alternate Storage > Configuration")

# CP-7 enhancements
for i in range(1, 7):
    names = {
        1: "Separation from primary site",
        2: "Accessibility",
        3: "Priority of service",
        4: "Preparation for use",
        5: "Equivalent information security safeguards",
        6: "Inability to return to primary site",
    }
    CP_ENH[f"CP-7({i})"] = (names[i], "Alternate Processing > Configuration")

# CP-8 enhancements
for i in range(1, 6):
    names = {
        1: "Priority of service provisions",
        2: "Single points of failure",
        3: "Separation of primary and alternate providers",
        4: "Provider contingency plan",
        5: "Alternate telecommunication service testing",
    }
    CP_ENH[f"CP-8({i})"] = (names[i], "Telecommunications > Redundancy")

# CP-9 enhancements
for i in range(1, 9):
    names = {
        1: "Testing for reliability and integrity",
        2: "Test restoration using sampling",
        3: "Separate storage for critical information",
        4: "Protection from unauthorized modification",
        5: "Transfer to alternate storage site",
        6: "Redundant secondary system",
        7: "Dual authorization for deletion or destruction",
        8: "Cryptographic protection",
    }
    CP_ENH[f"CP-9({i})"] = (names[i], "Backup > Configuration")

# CP-10 enhancements
for i in range(1, 7):
    names = {
        1: "Contingency plan testing (withdrawn)",
        2: "Transaction recovery",
        3: "Compensating security controls (withdrawn)",
        4: "Restore within time period",
        5: "Failover capability",
        6: "Component protection",
    }
    CP_ENH[f"CP-10({i})"] = (names[i], "Recovery > Configuration")

# CP-12(1), CP-13(1)
CP_ENH["CP-12(1)"] = ("Wide-area safe mode", "Systems > Safe Mode")
CP_ENH["CP-13(1)"] = ("Security mechanism performance testing", "Security > Alternate Mechanisms")

for ctrl_id, (summ, cp) in CP_ENH.items():
    base = ctrl_id.split("(")[0]
    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": [
            f"Implement {summ.lower()} controls",
            "Configure and document implementation",
            "Test effectiveness of enhancement",
            "Review and update annually",
        ],
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": ["config_snapshots", "test_reports"],
    }

# ============================================================
# IA — Identification and Authentication
# ============================================================

IA_BASE = {
    "IA-1": (
        "Develop, document, and disseminate identification and authentication policy",
        [
            "Draft identification and authentication policy",
            "Define authentication requirements by system type and risk level",
            "Establish authenticator management procedures",
            "Review and update policy annually",
        ],
        "Confluence > SEC Space > IA Policy",
        ["policy_document", "policy_review_date"],
    ),
    "IA-2": (
        "Uniquely identify and authenticate organizational users",
        [
            "Enable MFA for all interactive user accounts",
            "Configure identity provider with unique user identifiers",
            "Implement phishing-resistant MFA (FIDO2/WebAuthn)",
            "Verify MFA enrollment coverage for all users",
        ],
        "Okta > Security > Multifactor | Entra ID > MFA",
        ["iam_credential_report", "okta_users", "entra_users"],
    ),
    "IA-3": (
        "Authenticate devices before establishing connections",
        [
            "Implement 802.1X network access control for device authentication",
            "Configure certificate-based device authentication",
            "Deploy NAC solution for device posture assessment",
            "Block unauthenticated devices from network access",
        ],
        "NAC > Device Authentication | Intune > Compliance",
        ["config_snapshots", "intune_devices"],
    ),
    "IA-4": (
        "Manage system identifiers for users, processes, and devices",
        [
            "Implement unique identifier assignment process",
            "Prevent identifier reuse for defined period",
            "Disable identifiers after period of inactivity",
            "Maintain identifier lifecycle management",
        ],
        "IAM > Users | Entra ID > User Management",
        ["iam_users", "entra_users"],
    ),
    "IA-5": (
        "Manage system authenticators",
        [
            "Enforce password complexity (min 12 chars, mixed case, numbers, symbols)",
            "Implement password history (last 24 passwords)",
            "Configure password maximum age (90 days) or use passwordless",
            "Protect authenticator content from unauthorized disclosure",
        ],
        "IAM > Account Settings > Password Policy | Okta > Security > Authentication",
        ["iam_credential_report", "okta_policies"],
    ),
    "IA-6": (
        "Obscure authenticator feedback during authentication",
        [
            "Configure authentication interfaces to mask password entry",
            "Verify password masking on all login screens",
            "Test authenticator feedback obscuring",
            "Ensure credential display protection across all platforms",
        ],
        "Application > Authentication UI",
        ["config_snapshots"],
    ),
    "IA-7": (
        "Authenticate using cryptographic mechanisms to approved standards",
        [
            "Implement FIPS 140-2 validated cryptographic modules",
            "Configure TLS 1.2+ for all authentication flows",
            "Use approved algorithms for authenticator protection",
            "Verify cryptographic module compliance",
        ],
        "KMS > Key Configuration | TLS > Settings",
        ["config_snapshots"],
    ),
    "IA-8": (
        "Authenticate non-organizational users",
        [
            "Configure authentication for external users and partners",
            "Implement B2B federation for partner access",
            "Require MFA for non-organizational users",
            "Monitor non-organizational user access",
        ],
        "Entra ID > External Identities | Okta > External IdP",
        ["entra_users", "config_snapshots"],
    ),
    "IA-9": (
        "Identify and authenticate services",
        [
            "Implement service-to-service authentication (mTLS, API keys, OAuth)",
            "Configure service mesh with mutual TLS",
            "Verify service identity before accepting connections",
            "Rotate service credentials regularly",
        ],
        "Service Mesh > mTLS | API Gateway > Service Auth",
        ["config_snapshots"],
    ),
    "IA-10": (
        "Adaptive identification and authentication",
        [
            "Implement risk-based authentication policies",
            "Configure adaptive MFA based on context (location, device, behavior)",
            "Set up step-up authentication for high-risk activities",
            "Monitor adaptive authentication decisions",
        ],
        "Okta > Policies > Adaptive MFA | Entra ID > Conditional Access",
        ["okta_policies", "entra_conditional_access_policies"],
    ),
    "IA-11": (
        "Re-authentication",
        [
            "Configure re-authentication for privileged operations",
            "Set session re-authentication intervals",
            "Implement step-up authentication for sensitive transactions",
            "Verify re-authentication enforcement",
        ],
        "Application > Session > Re-Authentication",
        ["config_snapshots"],
    ),
    "IA-12": (
        "Identity proofing",
        [
            "Implement identity proofing process for user registration",
            "Verify identity using government-issued ID or equivalent",
            "Maintain identity proofing records",
            "Review identity proofing procedures annually",
        ],
        "HR > Identity Verification | Okta > Registration",
        ["identity_proofing_records"],
    ),
    "IA-13": (
        "Identity providers and authorization servers",
        [
            "Deploy enterprise identity provider (Okta, Entra ID)",
            "Configure OAuth 2.0/OIDC authorization server",
            "Implement token management and revocation",
            "Monitor identity provider health and security",
        ],
        "Okta > Applications > Auth Server | Entra ID > App Registrations",
        ["config_snapshots"],
    ),
}

for ctrl_id, (summ, steps, cp, evid) in IA_BASE.items():
    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": evid,
    }

# IA-2 enhancements
IA2_ENH = {
    "1": "Multi-factor authentication to privileged accounts",
    "2": "Multi-factor authentication to non-privileged accounts",
    "3": "Local access to privileged accounts (withdrawn)",
    "4": "Local access to non-privileged accounts (withdrawn)",
    "5": "Individual authentication with group authentication",
    "6": "Access to accounts — separate device",
    "7": "Access to non-privileged accounts — separate device (withdrawn)",
    "8": "Access to accounts — replay resistant",
    "9": "Network access to non-privileged accounts (withdrawn)",
    "10": "Single sign-on",
    "11": "Remote access — separate device (withdrawn)",
    "12": "Acceptance of PIV credentials",
    "13": "Out-of-band authentication",
}

for enh_num, summ in IA2_ENH.items():
    CONTROLS[f"IA-2({enh_num})"] = {
        "summary": summ,
        "remediation_steps": [
            f"Implement {summ.lower()} controls"
            if "withdrawn" not in summ.lower()
            else "This enhancement has been withdrawn",
            "Configure MFA policies in identity provider"
            if "withdrawn" not in summ.lower()
            else "Verify base control IA-2 is implemented",
            "Verify enforcement across all access methods"
            if "withdrawn" not in summ.lower()
            else "No additional action required",
            "Test authentication controls"
            if "withdrawn" not in summ.lower()
            else "Document withdrawal acknowledgment",
        ],
        "console_path": "Okta > Security > MFA Policies | Entra ID > Authentication Methods",
        "recommended_reading": [f"NIST SP 800-53A Rev 5: IA-2({enh_num}) Assessment Procedures"],
        "evidence_types": ["okta_policies", "entra_conditional_access_policies"],
    }

# IA-3 through IA-9 enhancements
for ctrl_base, max_enh, names_dict in [
    (
        "IA-3",
        4,
        {
            1: "Cryptographic bidirectional authentication",
            2: "Cryptographic bidirectional network authentication",
            3: "Dynamic address allocation",
            4: "Attestation",
        },
    ),
    (
        "IA-4",
        9,
        {
            1: "Prohibit account identifiers as public identifiers",
            2: "Supervisor authorization",
            3: "Multiple forms of certification",
            4: "Identify user status",
            5: "Dynamic management",
            6: "Cross-organization management",
            7: "In-person registration",
            8: "Pairwise pseudonymous identifiers",
            9: "Attribute maintenance and protection",
        },
    ),
    (
        "IA-5",
        18,
        {
            1: "Password-based authentication",
            2: "PKI-based authentication",
            3: "In-person or trusted third-party registration",
            4: "Automated support for password strength",
            5: "Change authenticators prior to delivery",
            6: "Protection of authenticators",
            7: "No embedded unencrypted static authenticators",
            8: "Multiple system accounts",
            9: "Federated credential management",
            10: "Dynamic credential binding",
            11: "Hardware token-based authentication",
            12: "Biometric authentication",
            13: "Expiration of cached authenticators",
            14: "Managing content of PKI trust stores",
            15: "GSA-approved products and services",
            16: "In-person or trusted third-party issuer",
            17: "Presentation attack detection for biometric authenticators",
            18: "Password managers",
        },
    ),
    ("IA-6", 1, {1: "Authentication feedback methods"}),
    (
        "IA-7",
        2,
        {
            1: "Hardware-based cryptographic authentication",
            2: "Software-based cryptographic authentication",
        },
    ),
    (
        "IA-8",
        6,
        {
            1: "Acceptance of PIV credentials from other agencies",
            2: "Acceptance of third-party credentials",
            3: "Use of FICAM-approved products",
            4: "Use of defined profiles",
            5: "Acceptance of PIV-I credentials",
            6: "Disassociability",
        },
    ),
    ("IA-9", 2, {1: "Information exchange", 2: "Transmission of decisions"}),
    ("IA-10", 1, {1: "Historical biometrics"}),
    ("IA-11", 1, {1: "Hardware token-based re-authentication"}),
    (
        "IA-12",
        6,
        {
            1: "Supervisor authorization",
            2: "Identity evidence",
            3: "Identity evidence validation and verification",
            4: "In-person validation and verification",
            5: "Address confirmation",
            6: "Accept externally-proofed identities",
        },
    ),
]:
    for enh_num in range(1, max_enh + 1):
        ctrl_enh_id = f"{ctrl_base}({enh_num})"
        if ctrl_enh_id not in CONTROLS:
            summ = names_dict.get(enh_num, f"Enhancement {enh_num}")
            CONTROLS[ctrl_enh_id] = {
                "summary": summ,
                "remediation_steps": [
                    f"Implement {summ.lower()}"
                    if "withdrawn" not in summ.lower()
                    else "This enhancement has been withdrawn",
                    "Configure in identity provider or authentication system",
                    "Verify enforcement through testing",
                    "Document implementation and review annually",
                ],
                "console_path": f"{ctrl_base} > Enhancement Configuration",
                "recommended_reading": [
                    f"NIST SP 800-53A Rev 5: {ctrl_enh_id} Assessment Procedures"
                ],
                "evidence_types": ["config_snapshots"],
            }

# ============================================================
# IR — Incident Response
# ============================================================

IR_BASE = {
    "IR-1": (
        "Develop, document, and disseminate incident response policy",
        [
            "Draft incident response policy and procedures",
            "Define incident categories and severity levels",
            "Establish incident response team roles and responsibilities",
            "Review and update policy annually",
        ],
        "Confluence > SEC Space > Incident Response Policy",
        ["policy_document", "policy_review_date"],
    ),
    "IR-2": (
        "Provide incident response training",
        [
            "Conduct initial incident response training for IR team",
            "Provide annual refresher training",
            "Include role-specific IR training content",
            "Document training completion",
        ],
        "KnowBe4 > Training > Incident Response",
        ["training_records"],
    ),
    "IR-3": (
        "Test the incident response capability",
        [
            "Conduct annual incident response exercises",
            "Include tabletop and simulated incident exercises",
            "Document exercise results and lessons learned",
            "Update IR plan based on exercise findings",
        ],
        "GRC Platform > IR Exercises",
        ["test_reports"],
    ),
    "IR-4": (
        "Implement an incident handling capability",
        [
            "Establish incident response process (detect, analyze, contain, eradicate, recover)",
            "Configure SIEM/SOAR for incident handling workflows",
            "Define escalation procedures and communication plans",
            "Track and close incidents with documented resolution",
        ],
        "Sentinel > Incidents | PagerDuty > Incidents",
        ["siem_alerts", "incident_records"],
    ),
    "IR-5": (
        "Track and document incidents",
        [
            "Implement incident tracking system",
            "Record all incidents with required details",
            "Maintain incident database with classification and resolution",
            "Generate incident metrics and reports monthly",
        ],
        "SIEM > Incident Tracking | ServiceNow > Security Incidents",
        ["incident_records", "siem_alerts"],
    ),
    "IR-6": (
        "Report incidents to appropriate authorities",
        [
            "Define incident reporting requirements and thresholds",
            "Establish external reporting procedures (CISA, law enforcement)",
            "Configure automated reporting for qualifying incidents",
            "Document reporting timelines and contacts",
        ],
        "Incident Response > Reporting Procedures",
        ["incident_records"],
    ),
    "IR-7": (
        "Provide incident response assistance",
        [
            "Establish incident response support resources",
            "Configure help desk for incident reporting",
            "Provide incident response guidance to all users",
            "Maintain incident response contact list",
        ],
        "ServiceNow > Incident Support | Help Desk",
        ["incident_records"],
    ),
    "IR-8": (
        "Develop incident response plan",
        [
            "Document comprehensive incident response plan",
            "Define incident categories, severity, and response procedures",
            "Identify external resources and coordination points",
            "Review and update plan annually",
        ],
        "Confluence > SEC Space > IR Plan",
        ["policy_document"],
    ),
    "IR-9": (
        "Information spillage response",
        [
            "Define information spillage response procedures",
            "Identify responsible personnel for spillage incidents",
            "Implement containment procedures for data spillage",
            "Document spillage incident handling and resolution",
        ],
        "Incident Response > Spillage Procedures",
        ["policy_document"],
    ),
    "IR-10": (
        "Integrated information security analysis team",
        [
            "Establish integrated security analysis team",
            "Define team composition and responsibilities",
            "Provide team with necessary tools and access",
            "Review team effectiveness annually",
        ],
        "Security Operations > Analysis Team",
        ["policy_document"],
    ),
}

for ctrl_id, (summ, steps, cp, evid) in IR_BASE.items():
    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": evid,
    }

# IR enhancements
IR_ENH_DEFS = {
    "IR-1(1)": "Automation support for incident response policy management",
    "IR-2(1)": "Simulated events in IR training",
    "IR-2(2)": "Automated IR training environments",
    "IR-2(3)": "Breach response training",
    "IR-3(1)": "Automated IR testing",
    "IR-3(2)": "Coordination with related plans testing",
    "IR-3(3)": "Continuous improvement from IR testing",
    "IR-4(1)": "Automated incident handling processes",
    "IR-4(2)": "Dynamic reconfiguration",
    "IR-4(3)": "Continuity of operations",
    "IR-4(4)": "Information correlation",
    "IR-4(5)": "Automatic disable of system",
    "IR-4(6)": "Insider threats",
    "IR-4(7)": "Insider threats — intra-organization coordination",
    "IR-4(8)": "Correlation with external organizations",
    "IR-4(9)": "Dynamic response capability",
    "IR-4(10)": "Supply chain coordination",
    "IR-4(11)": "Integrated incident response team",
    "IR-4(12)": "Malicious code and forensic analysis",
    "IR-4(13)": "Behavior analysis",
    "IR-4(14)": "Security operations center",
    "IR-5(1)": "Automated incident tracking and reporting",
    "IR-6(1)": "Automated reporting",
    "IR-6(2)": "Vulnerabilities related to incidents",
    "IR-6(3)": "Supply chain coordination",
    "IR-7(1)": "Automation support for availability of information and support",
    "IR-7(2)": "Coordination with external providers",
    "IR-8(1)": "Breaches",
    "IR-9(1)": "Responsible personnel for spillage response",
    "IR-9(2)": "Training for spillage response",
    "IR-9(3)": "Post-spillage operations",
    "IR-9(4)": "Exposure to unauthorized personnel",
    "IR-10(1)": "Forensic analysis team",
}

for ctrl_id, summ in IR_ENH_DEFS.items():
    if ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Configure supporting tools and processes",
                "Test and verify effectiveness",
                "Document and review annually",
            ],
            "console_path": "Incident Response > " + ctrl_id.split("(")[0].split("-")[1],
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["incident_records", "config_snapshots"],
        }

# ============================================================
# Remaining families - batch generation
# ============================================================

# MA — Maintenance
MA_DEFS = {
    "MA-1": (
        "Develop, document, and disseminate maintenance policy and procedures",
        [
            "Draft system maintenance policy",
            "Define maintenance roles and responsibilities",
            "Establish maintenance scheduling requirements",
            "Review and update policy annually",
        ],
        "Confluence > SEC Space > Maintenance Policy",
        ["policy_document"],
    ),
    "MA-2": (
        "Schedule, perform, document, and review maintenance on system components",
        [
            "Implement preventive maintenance schedule for all components",
            "Document all maintenance activities",
            "Review maintenance records for completeness",
            "Verify maintenance does not introduce vulnerabilities",
        ],
        "ServiceNow > Change Management > Maintenance",
        ["maintenance_records"],
    ),
    "MA-3": (
        "Approve, control, and monitor maintenance tools",
        [
            "Maintain approved maintenance tools inventory",
            "Inspect maintenance tools before use",
            "Monitor maintenance tool usage",
            "Remove unauthorized maintenance tools",
        ],
        "CMDB > Maintenance Tools",
        ["asset_inventory"],
    ),
    "MA-4": (
        "Approve and monitor nonlocal maintenance activities",
        [
            "Implement secure remote maintenance access",
            "Require MFA for remote maintenance sessions",
            "Log and monitor all remote maintenance activities",
            "Terminate remote maintenance sessions when complete",
        ],
        "PAM > Remote Maintenance | VPN > Maintenance Access",
        ["audit_logs"],
    ),
    "MA-5": (
        "Establish a process for maintenance personnel authorization",
        [
            "Verify maintenance personnel security clearance",
            "Escort unauthorized maintenance personnel",
            "Supervise maintenance activities by non-cleared personnel",
            "Document maintenance personnel authorization",
        ],
        "HR > Contractor Verification | Badge System",
        ["personnel_records"],
    ),
    "MA-6": (
        "Obtain maintenance support and spare parts within defined time period",
        [
            "Maintain spare parts inventory for critical components",
            "Establish maintenance support agreements (SLAs)",
            "Track spare parts availability",
            "Review maintenance support agreements annually",
        ],
        "ServiceNow > Asset Management > Spare Parts",
        ["maintenance_records"],
    ),
    "MA-7": (
        "Field maintenance",
        [
            "Define field maintenance procedures and restrictions",
            "Implement security controls for field maintenance",
            "Verify field maintenance does not compromise security",
            "Document field maintenance activities",
        ],
        "ServiceNow > Field Service > Maintenance",
        ["maintenance_records"],
    ),
}

for ctrl_id, (summ, steps, cp, evid) in MA_DEFS.items():
    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": evid,
    }

# MP — Media Protection
MP_DEFS = {
    "MP-1": (
        "Develop, document, and disseminate media protection policy and procedures",
        [
            "Draft media protection policy",
            "Define media handling and classification requirements",
            "Establish media disposal procedures",
            "Review and update policy annually",
        ],
        "Confluence > SEC Space > Media Protection Policy",
        ["policy_document"],
    ),
    "MP-2": (
        "Restrict access to digital and non-digital media",
        [
            "Implement physical access controls for media storage",
            "Restrict digital media access through encryption and access controls",
            "Document media access authorization",
            "Review media access controls quarterly",
        ],
        "Physical Security > Media Storage",
        ["config_snapshots"],
    ),
    "MP-3": (
        "Mark media with applicable security markings",
        [
            "Implement media labeling procedures",
            "Apply classification markings to all media",
            "Verify marking accuracy during handling",
            "Train personnel on media marking requirements",
        ],
        "Data Classification > Labeling",
        ["policy_document"],
    ),
    "MP-4": (
        "Physically control and securely store media",
        [
            "Store media in controlled areas with physical access controls",
            "Implement environmental protections for media storage",
            "Track media location and custody",
            "Review media storage controls annually",
        ],
        "Physical Security > Media Storage Facility",
        ["config_snapshots"],
    ),
    "MP-5": (
        "Protect and control media during transport",
        [
            "Implement media transport security procedures",
            "Use encrypted containers for media in transit",
            "Track media during transport",
            "Verify media integrity upon receipt",
        ],
        "Logistics > Secure Transport",
        ["policy_document"],
    ),
    "MP-6": (
        "Sanitize media before disposal or reuse",
        [
            "Implement media sanitization procedures (NIST SP 800-88)",
            "Use approved sanitization tools and methods",
            "Verify sanitization completeness",
            "Document sanitization activities and maintain certificates",
        ],
        "IT Operations > Media Sanitization",
        ["sanitization_records"],
    ),
    "MP-7": (
        "Restrict use of portable storage devices",
        [
            "Define portable storage device usage policy",
            "Implement USB device control through endpoint protection",
            "Block unauthorized portable storage devices",
            "Monitor portable storage device usage",
        ],
        "Intune > Device Configuration > USB Restrictions",
        ["intune_devices"],
    ),
    "MP-8": (
        "Media downgrading",
        [
            "Define media downgrading procedures",
            "Implement approved downgrading methods",
            "Verify downgrading completeness",
            "Document downgrading activities",
        ],
        "Data Classification > Downgrading",
        ["policy_document"],
    ),
}

for ctrl_id, (summ, steps, cp, evid) in MP_DEFS.items():
    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": evid,
    }

# PE — Physical and Environmental Protection
PE_DEFS = {
    "PE-1": (
        "Develop, document, and disseminate physical and environmental protection policy",
        [
            "Draft physical and environmental protection policy",
            "Define facility access requirements",
            "Establish environmental control requirements",
            "Review and update policy annually",
        ],
        "Confluence > SEC Space > Physical Security Policy",
        ["policy_document"],
    ),
    "PE-2": (
        "Develop, approve, and maintain physical access authorizations",
        [
            "Maintain list of authorized personnel for facility access",
            "Issue access credentials (badges) to authorized personnel",
            "Review and update access authorizations quarterly",
            "Remove access authorizations upon termination",
        ],
        "Badge System > Access Authorizations",
        ["badge_records"],
    ),
    "PE-3": (
        "Enforce physical access authorizations at facility entry points",
        [
            "Implement badge readers and access control at all entry points",
            "Deploy security guards or video surveillance at entry points",
            "Log all physical access events",
            "Monitor access logs for anomalies",
        ],
        "Badge System > Access Control | CCTV > Monitoring",
        ["badge_records", "cctv_logs"],
    ),
    "PE-4": (
        "Control physical access to information system distribution and transmission lines",
        [
            "Protect network cabling and distribution points",
            "Restrict access to server rooms and network closets",
            "Monitor access to distribution infrastructure",
            "Inspect physical infrastructure regularly",
        ],
        "Facilities > Network Infrastructure Access",
        ["badge_records"],
    ),
    "PE-5": (
        "Control physical access to information system output devices",
        [
            "Restrict access to printers, screens, and output devices",
            "Implement follow-me printing",
            "Position displays to prevent shoulder surfing",
            "Secure output device locations",
        ],
        "Facilities > Output Device Security",
        ["config_snapshots"],
    ),
    "PE-6": (
        "Monitor physical access to the facility",
        [
            "Implement physical access monitoring and logging",
            "Review physical access logs regularly",
            "Investigate unauthorized access attempts",
            "Maintain monitoring system availability",
        ],
        "Badge System > Access Logs | CCTV > Live Monitoring",
        ["badge_records", "cctv_logs"],
    ),
    "PE-7": (
        "Control physical access by visitors (withdrawn - incorporated into PE-2 and PE-3)",
        [
            "This control has been withdrawn",
            "Verify PE-2 and PE-3 visitor controls are implemented",
        ],
        "See PE-2 and PE-3",
        ["policy_document"],
    ),
    "PE-8": (
        "Maintain visitor access records",
        [
            "Log all visitor entries and exits",
            "Require visitor escort in controlled areas",
            "Retain visitor logs per retention policy",
            "Review visitor logs weekly",
        ],
        "Badge System > Visitor Management",
        ["visitor_logs"],
    ),
    "PE-9": (
        "Protect power equipment and power cabling",
        [
            "Install physical protections for power infrastructure",
            "Restrict access to power equipment",
            "Implement redundant power supplies (UPS)",
            "Inspect power infrastructure regularly",
        ],
        "Facilities > Power Infrastructure",
        ["maintenance_records"],
    ),
    "PE-10": (
        "Provide emergency shutoff capability",
        [
            "Install emergency power shutoff switches",
            "Label and test emergency shutoffs quarterly",
            "Document emergency shutoff procedures",
            "Train personnel on emergency shutoff use",
        ],
        "Facilities > Emergency Power Controls",
        ["test_reports"],
    ),
    "PE-11": (
        "Provide uninterruptible power supply",
        [
            "Deploy UPS for critical systems",
            "Configure UPS monitoring and alerting",
            "Test UPS failover quarterly",
            "Maintain UPS batteries per manufacturer schedule",
        ],
        "Facilities > UPS > Configuration",
        ["maintenance_records"],
    ),
    "PE-12": (
        "Provide emergency lighting",
        [
            "Install emergency lighting in all occupied areas",
            "Test emergency lighting monthly",
            "Maintain emergency lighting batteries",
            "Document emergency lighting coverage",
        ],
        "Facilities > Emergency Lighting",
        ["maintenance_records"],
    ),
    "PE-13": (
        "Protect the facility from fire",
        [
            "Install fire detection and suppression systems",
            "Maintain fire suppression equipment per code",
            "Conduct fire drills annually",
            "Document fire protection system maintenance",
        ],
        "Facilities > Fire Protection",
        ["maintenance_records"],
    ),
    "PE-14": (
        "Maintain temperature and humidity controls",
        [
            "Configure HVAC for appropriate temperature and humidity",
            "Implement temperature and humidity monitoring with alerts",
            "Set acceptable ranges per equipment specifications",
            "Document environmental monitoring records",
        ],
        "Facilities > Environmental Monitoring > HVAC",
        ["environmental_logs"],
    ),
    "PE-15": (
        "Protect against water damage",
        [
            "Implement water detection sensors in server rooms",
            "Configure water detection alerts",
            "Install shutoff valves for water sources near equipment",
            "Document water damage prevention measures",
        ],
        "Facilities > Water Detection",
        ["environmental_logs"],
    ),
    "PE-16": (
        "Control delivery and removal of system components",
        [
            "Implement delivery and receiving procedures",
            "Inspect deliveries for tampering",
            "Log all component deliveries and removals",
            "Restrict delivery access to designated areas",
        ],
        "Facilities > Loading Dock > Security",
        ["asset_inventory"],
    ),
    "PE-17": (
        "Alternate work site security",
        [
            "Define security requirements for alternate work sites",
            "Verify security controls at alternate sites",
            "Provide VPN and encryption for remote work",
            "Review alternate work site security annually",
        ],
        "IT > Remote Work > Security Requirements",
        ["config_snapshots"],
    ),
    "PE-18": (
        "Location of system components",
        [
            "Position systems to minimize physical threat exposure",
            "Locate critical systems away from windows and external walls",
            "Document component placement rationale",
            "Review component locations during facility changes",
        ],
        "Facilities > Data Center > Layout",
        ["config_snapshots"],
    ),
    "PE-19": (
        "Information leakage through electromagnetic emanations",
        [
            "Implement TEMPEST or electromagnetic shielding where required",
            "Position equipment to minimize emanation exposure",
            "Test for electromagnetic leakage",
            "Document emanation protection measures",
        ],
        "Facilities > TEMPEST > Shielding",
        ["config_snapshots"],
    ),
    "PE-20": (
        "Asset monitoring and tracking",
        [
            "Implement RFID or barcode tracking for physical assets",
            "Configure automated asset location tracking",
            "Alert on unauthorized asset movement",
            "Reconcile physical asset inventory quarterly",
        ],
        "Asset Management > Tracking",
        ["asset_inventory"],
    ),
    "PE-21": (
        "Electromagnetic pulse protection",
        [
            "Implement EMP protection for critical systems",
            "Install EMP shielding on critical infrastructure",
            "Test EMP protection effectiveness",
            "Document EMP protection measures",
        ],
        "Facilities > EMP Protection",
        ["config_snapshots"],
    ),
    "PE-22": (
        "Component marking",
        [
            "Mark system components with security designations",
            "Implement asset tagging for all components",
            "Verify marking accuracy during inventory",
            "Update markings on component changes",
        ],
        "Asset Management > Component Marking",
        ["asset_inventory"],
    ),
    "PE-23": (
        "Facility location",
        [
            "Select facility location based on threat assessment",
            "Consider natural disaster, physical threat, and environmental factors",
            "Document location selection rationale",
            "Reassess location suitability on significant threat changes",
        ],
        "Facilities > Site Selection",
        ["policy_document"],
    ),
}

for ctrl_id, (summ, steps, cp, evid) in PE_DEFS.items():
    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": cp,
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": evid,
    }

# ============================================================
# Remaining families: PL, PM, PS, PT, RA, SA, SC, SI, SR
# These will be generated with appropriate content
# ============================================================

# PL — Planning
PL_DEFS = {
    "PL-1": "Develop, document, and disseminate security and privacy planning policy",
    "PL-2": "Develop and maintain a system security and privacy plan (SSP)",
    "PL-3": "System security plan update (withdrawn - incorporated into PL-2)",
    "PL-4": "Establish rules of behavior for system users",
    "PL-5": "Privacy impact assessment (withdrawn - incorporated into RA-8)",
    "PL-6": "Security-related activity planning (withdrawn - incorporated into PL-2)",
    "PL-7": "Concept of operations",
    "PL-8": "Security and privacy architectures",
    "PL-9": "Central management of security and privacy plans",
    "PL-10": "Baseline selection",
    "PL-11": "Baseline tailoring",
}

for ctrl_id, summ in PL_DEFS.items():
    if ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"{'This control has been withdrawn' if 'withdrawn' in summ.lower() else summ}",
                "Document implementation details"
                if "withdrawn" not in summ.lower()
                else "Verify replacement control is implemented",
                "Review and update annually"
                if "withdrawn" not in summ.lower()
                else "No additional action required",
                "Distribute to relevant stakeholders"
                if "withdrawn" not in summ.lower()
                else "Document withdrawal acknowledgment",
            ],
            "console_path": "Confluence > SEC Space > Planning",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["policy_document"],
        }

# PM — Program Management
PM_DEFS = {
    "PM-1": "Information security and privacy program plan",
    "PM-2": "Information security and privacy program leadership role",
    "PM-3": "Information security and privacy resources",
    "PM-4": "Plan of action and milestones process",
    "PM-5": "System inventory",
    "PM-6": "Measures of performance",
    "PM-7": "Enterprise architecture",
    "PM-8": "Critical infrastructure plan",
    "PM-9": "Risk management strategy",
    "PM-10": "Authorization process",
    "PM-11": "Mission and business process definition",
    "PM-12": "Insider threat program",
    "PM-13": "Security and privacy workforce",
    "PM-14": "Testing, training, and monitoring",
    "PM-15": "Security and privacy groups and associations",
    "PM-16": "Threat awareness program",
    "PM-17": "Protecting controlled unclassified information on external systems",
    "PM-18": "Privacy program plan",
    "PM-19": "Privacy program leadership role",
    "PM-20": "Dissemination of privacy program information",
    "PM-21": "Accounting of disclosures",
    "PM-22": "Personally identifiable information quality management",
    "PM-23": "Data governance body",
    "PM-24": "Data integrity board",
    "PM-25": "Minimization of personally identifiable information used in testing",
    "PM-26": "Complaint management",
    "PM-27": "Privacy reporting",
    "PM-28": "Risk framing",
    "PM-29": "Risk management program leadership roles",
    "PM-30": "Supply chain risk management strategy",
    "PM-31": "Continuous monitoring strategy",
    "PM-32": "Purposing",
}

for ctrl_id, summ in PM_DEFS.items():
    if ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document program management details",
                "Assign responsible personnel",
                "Review and update annually",
            ],
            "console_path": "GRC Platform > Program Management",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["policy_document"],
        }

# PS — Personnel Security
PS_DEFS = {
    "PS-1": "Develop, document, and disseminate personnel security policy",
    "PS-2": "Position risk designation",
    "PS-3": "Personnel screening",
    "PS-4": "Personnel termination",
    "PS-5": "Personnel transfer",
    "PS-6": "Access agreements",
    "PS-7": "External personnel security",
    "PS-8": "Personnel sanctions",
    "PS-9": "Position descriptions",
}

for ctrl_id, summ in PS_DEFS.items():
    if ctrl_id not in CONTROLS:
        steps = {
            "PS-1": [
                "Draft personnel security policy",
                "Define screening and access agreement requirements",
                "Establish personnel security review cycle",
                "Distribute policy to HR and management",
            ],
            "PS-2": [
                "Assign risk designations to all positions",
                "Review risk designations when position duties change",
                "Document risk designation criteria",
                "Update designations at least every 3 years",
            ],
            "PS-3": [
                "Conduct background screening before granting access",
                "Screen at level commensurate with position risk",
                "Re-screen personnel at defined intervals",
                "Document screening results",
            ],
            "PS-4": [
                "Disable system access upon termination notification",
                "Retrieve all organizational assets and credentials",
                "Conduct exit interview covering security obligations",
                "Complete termination checklist within 24 hours",
            ],
            "PS-5": [
                "Review and update access rights upon personnel transfer",
                "Initiate access modification within 24 hours of transfer",
                "Remove access no longer needed in new role",
                "Document transfer access changes",
            ],
            "PS-6": [
                "Require signed access agreements before granting access",
                "Include acceptable use and security responsibilities",
                "Re-sign agreements annually or on significant policy changes",
                "Maintain signed agreement records",
            ],
            "PS-7": [
                "Establish security requirements for external personnel",
                "Include security clauses in contracts",
                "Monitor external personnel compliance",
                "Terminate access for non-compliant external personnel",
            ],
            "PS-8": [
                "Define sanctions for security policy violations",
                "Apply sanctions consistently per policy",
                "Document all sanctions and corrective actions",
                "Review sanctions process annually",
            ],
            "PS-9": [
                "Include security responsibilities in position descriptions",
                "Define security role requirements per position",
                "Update descriptions when responsibilities change",
                "Review position descriptions annually",
            ],
        }.get(
            ctrl_id,
            [
                f"Implement {summ.lower()}",
                "Document implementation",
                "Review annually",
                "Track compliance",
            ],
        )
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": steps,
            "console_path": "HR System > Personnel Security"
            if ctrl_id != "PS-1"
            else "Confluence > SEC Space > Personnel Security Policy",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["personnel_records", "policy_document"],
        }

# PT — Personally Identifiable Information Processing and Transparency
PT_DEFS = {
    "PT-1": "Policy and procedures for PII processing and transparency",
    "PT-2": "Authority to process personally identifiable information",
    "PT-3": "Personally identifiable information processing purposes",
    "PT-4": "Consent for PII processing",
    "PT-5": "Privacy notice",
    "PT-6": "System of records notice",
    "PT-7": "Specific categories of PII",
    "PT-8": "Computer matching requirements",
}

for ctrl_id, summ in PT_DEFS.items():
    if ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document PII processing authorities and purposes",
                "Maintain privacy notices and consent mechanisms",
                "Review and update annually",
            ],
            "console_path": "Privacy Portal > PII Management",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["policy_document", "privacy_records"],
        }

# RA — Risk Assessment
RA_DEFS = {
    "RA-1": "Develop, document, and disseminate risk assessment policy",
    "RA-2": "Categorize the system and information",
    "RA-3": "Conduct risk assessments",
    "RA-4": "Risk assessment update (withdrawn - incorporated into RA-3)",
    "RA-5": "Conduct vulnerability monitoring and scanning",
    "RA-6": "Technical surveillance countermeasures survey",
    "RA-7": "Risk response",
    "RA-8": "Privacy impact assessments",
    "RA-9": "Criticality analysis",
    "RA-10": "Threat hunting",
}

for ctrl_id, summ in RA_DEFS.items():
    if ctrl_id not in CONTROLS:
        steps_map = {
            "RA-1": [
                "Draft risk assessment policy",
                "Define risk assessment methodology (NIST RMF, FAIR)",
                "Establish assessment frequency and triggers",
                "Distribute policy to all personnel",
            ],
            "RA-2": [
                "Categorize system using FIPS 199 criteria",
                "Document security categorization in SSP",
                "Review categorization on significant system changes",
                "Validate categorization with authorizing official",
            ],
            "RA-3": [
                "Conduct annual risk assessment",
                "Identify threats, vulnerabilities, and impacts",
                "Calculate risk using approved methodology",
                "Document risk assessment results and recommendations",
            ],
            "RA-4": [
                "This control has been withdrawn and incorporated into RA-3",
                "Verify RA-3 risk assessment controls are implemented",
            ],
            "RA-5": [
                "Implement automated vulnerability scanning (Qualys, Tenable, Rapid7)",
                "Scan all systems at least monthly",
                "Remediate critical/high vulnerabilities within 30 days",
                "Track vulnerability metrics and report trends",
            ],
            "RA-6": [
                "Conduct TSCM surveys for facilities handling sensitive information",
                "Schedule surveys based on threat assessment",
                "Document survey results and findings",
                "Address identified surveillance threats",
            ],
            "RA-7": [
                "Define risk response strategies (accept, mitigate, transfer, avoid)",
                "Document risk response decisions",
                "Implement chosen risk response measures",
                "Monitor risk response effectiveness",
            ],
            "RA-8": [
                "Conduct privacy impact assessments for systems processing PII",
                "Document privacy risks and mitigations",
                "Review PIAs on significant system changes",
                "Publish PIAs as required",
            ],
            "RA-9": [
                "Conduct criticality analysis of system components",
                "Prioritize components by mission impact",
                "Document criticality designations",
                "Review criticality analysis on system changes",
            ],
            "RA-10": [
                "Implement threat hunting program",
                "Conduct proactive threat hunts based on threat intelligence",
                "Document threat hunting activities and findings",
                "Improve detection capabilities based on hunting results",
            ],
        }
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": steps_map.get(
                ctrl_id,
                [
                    f"Implement {summ.lower()}",
                    "Document implementation",
                    "Review annually",
                    "Track compliance",
                ],
            ),
            "console_path": "GRC Platform > Risk Assessment"
            if ctrl_id != "RA-5"
            else "Qualys > Scans | Tenable > Vulnerability Dashboard",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["risk_assessment", "policy_document"]
            if ctrl_id != "RA-5"
            else ["vulnerability_scans", "scan_reports"],
        }

# SA — System and Services Acquisition
SA_BASE_DEFS = {
    "SA-1": "Develop, document, and disseminate system and services acquisition policy",
    "SA-2": "Allocation of resources for security and privacy",
    "SA-3": "System development lifecycle processes",
    "SA-4": "Acquisition process for system and service requirements",
    "SA-5": "System documentation",
    "SA-6": "Software usage restrictions (withdrawn - incorporated into CM-10 and SI-7)",
    "SA-7": "User-installed software (withdrawn - incorporated into CM-11 and SI-7)",
    "SA-8": "Security and privacy engineering principles",
    "SA-9": "External system services",
    "SA-10": "Developer configuration management",
    "SA-11": "Developer testing and evaluation",
    "SA-12": "Supply chain protection (withdrawn - incorporated into SR family)",
    "SA-13": "Trustworthiness (withdrawn - incorporated into SA-8)",
    "SA-14": "Criticality analysis (withdrawn - incorporated into RA-9)",
    "SA-15": "Development process, standards, and tools",
    "SA-16": "Developer-provided training",
    "SA-17": "Developer security and privacy architecture and design",
    "SA-18": "Tamper resistance and detection (withdrawn - incorporated into SR-9)",
    "SA-19": "Component authenticity (withdrawn - incorporated into SR-11)",
    "SA-20": "Customized development of critical components",
    "SA-21": "Developer screening",
    "SA-22": "Unsupported system components",
    "SA-23": "Specialization",
}

for ctrl_id, summ in SA_BASE_DEFS.items():
    if ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"{'This control has been withdrawn' if 'withdrawn' in summ.lower() else 'Implement ' + summ.lower()}",
                "Document implementation requirements"
                if "withdrawn" not in summ.lower()
                else "Verify replacement control is implemented",
                "Review and update annually"
                if "withdrawn" not in summ.lower()
                else "No additional action required",
                "Verify compliance with acquisition requirements"
                if "withdrawn" not in summ.lower()
                else "Document withdrawal acknowledgment",
            ],
            "console_path": "GRC Platform > Acquisition"
            if ctrl_id != "SA-11"
            else "CI/CD > Security Testing | Snyk > Code | SonarQube",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["policy_document"]
            if ctrl_id != "SA-11"
            else ["code_scan_results", "test_reports"],
        }

# SC — System and Communications Protection
SC_BASE_DEFS = {
    "SC-1": "Develop, document, and disseminate system and communications protection policy",
    "SC-2": "Separation of system and user functionality",
    "SC-3": "Security function isolation",
    "SC-4": "Information in shared system resources",
    "SC-5": "Denial-of-service protection",
    "SC-6": "Resource availability",
    "SC-7": "Boundary protection",
    "SC-8": "Transmission confidentiality and integrity",
    "SC-9": "Transmission confidentiality (withdrawn - incorporated into SC-8)",
    "SC-10": "Network disconnect after defined period",
    "SC-11": "Trusted path",
    "SC-12": "Cryptographic key establishment and management",
    "SC-13": "Cryptographic protection",
    "SC-14": "Public access protections (withdrawn - incorporated into AC-2, AC-3, AC-5, SI-3, SI-4)",
    "SC-15": "Collaborative computing devices and applications",
    "SC-16": "Transmission of security and privacy attributes",
    "SC-17": "Public key infrastructure certificates",
    "SC-18": "Mobile code",
    "SC-19": "Voice over internet protocol (withdrawn - incorporated into CM-7)",
    "SC-20": "Secure name/address resolution service (authoritative source)",
    "SC-21": "Secure name/address resolution service (recursive or caching resolver)",
    "SC-22": "Architecture and provisioning for name/address resolution service",
    "SC-23": "Session authenticity",
    "SC-24": "Fail in known state",
    "SC-25": "Thin nodes",
    "SC-26": "Decoys",
    "SC-27": "Platform-independent applications",
    "SC-28": "Protection of information at rest",
    "SC-29": "Heterogeneity",
    "SC-30": "Concealment and misdirection",
    "SC-31": "Covert channel analysis",
    "SC-32": "System partitioning",
    "SC-33": "Transmission preparation integrity (withdrawn - incorporated into SC-8)",
    "SC-34": "Non-modifiable executable programs",
    "SC-35": "External malicious code identification",
    "SC-36": "Distributed processing and storage",
    "SC-37": "Out-of-band channels",
    "SC-38": "Operations security",
    "SC-39": "Process isolation",
    "SC-40": "Wireless link protection",
    "SC-41": "Port and I/O device access",
    "SC-42": "Sensor capability and data",
    "SC-43": "Usage restrictions",
    "SC-44": "Detonation chambers",
    "SC-45": "System time synchronization",
    "SC-46": "Cross domain policy enforcement",
    "SC-47": "Alternate communications paths",
    "SC-48": "Sensor relocation",
    "SC-49": "Hardware-enforced separation and policy enforcement",
    "SC-50": "Software-enforced separation and policy enforcement",
    "SC-51": "Hardware-based protection",
}

for ctrl_id, summ in SC_BASE_DEFS.items():
    if ctrl_id not in CONTROLS:
        is_withdrawn = "withdrawn" in summ.lower()
        console = "Network > Security Configuration"
        if ctrl_id == "SC-7":
            console = "VPC > Security Groups | WAF > Rules | NACLs"
        elif ctrl_id == "SC-28":
            console = "KMS > Keys | S3 > Encryption | RDS > Encryption"
        elif ctrl_id == "SC-8":
            console = "ACM > Certificates | TLS Configuration"
        elif ctrl_id == "SC-12":
            console = "KMS > Key Management | HSM"
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                "This control has been withdrawn" if is_withdrawn else f"Implement {summ.lower()}",
                "Verify replacement control is implemented"
                if is_withdrawn
                else "Configure security controls in network and system settings",
                "No additional action required"
                if is_withdrawn
                else "Verify effectiveness through testing",
                "Document withdrawal acknowledgment"
                if is_withdrawn
                else "Review and update configuration annually",
            ],
            "console_path": console,
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["config_snapshots", "network_config"]
            if not is_withdrawn
            else ["policy_document"],
        }

# SI — System and Information Integrity
SI_BASE_DEFS = {
    "SI-1": "Develop, document, and disseminate system and information integrity policy",
    "SI-2": "Flaw remediation through patching and updates",
    "SI-3": "Malicious code protection",
    "SI-4": "System monitoring for attacks and indicators of compromise",
    "SI-5": "Security alerts, advisories, and directives",
    "SI-6": "Security and privacy function verification",
    "SI-7": "Software, firmware, and information integrity",
    "SI-8": "Spam protection",
    "SI-9": "Information input restrictions (withdrawn - incorporated into AC-2, AC-3, AC-5, AC-6)",
    "SI-10": "Information input validation",
    "SI-11": "Error handling",
    "SI-12": "Information management and retention",
    "SI-13": "Predictable failure prevention",
    "SI-14": "Non-persistence",
    "SI-15": "Information output filtering",
    "SI-16": "Memory protection",
    "SI-17": "Fail-safe procedures",
    "SI-18": "Personally identifiable information quality operations",
    "SI-19": "De-identification",
    "SI-20": "Tainting",
    "SI-21": "Information refresh",
    "SI-22": "Information diversity",
    "SI-23": "Information fragmentation",
}

for ctrl_id, summ in SI_BASE_DEFS.items():
    if ctrl_id not in CONTROLS:
        is_withdrawn = "withdrawn" in summ.lower()
        console = "Security Center > System Integrity"
        if ctrl_id == "SI-2":
            console = "SSM > Patch Manager | Qualys > Patching"
        elif ctrl_id == "SI-3":
            console = "Endpoint Protection > Antimalware | CrowdStrike"
        elif ctrl_id == "SI-4":
            console = "GuardDuty > Findings | Sentinel > Analytics | SIEM"
        elif ctrl_id == "SI-5":
            console = "Security Hub > Standards | Defender > Recommendations"
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                "This control has been withdrawn" if is_withdrawn else f"Implement {summ.lower()}",
                "Verify replacement control is implemented"
                if is_withdrawn
                else "Configure monitoring and alerting",
                "No additional action required"
                if is_withdrawn
                else "Verify effectiveness through testing",
                "Document withdrawal acknowledgment"
                if is_withdrawn
                else "Review and update annually",
            ],
            "console_path": console,
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["config_snapshots"] if not is_withdrawn else ["policy_document"],
        }

# SR — Supply Chain Risk Management
SR_BASE_DEFS = {
    "SR-1": "Develop, document, and disseminate supply chain risk management policy",
    "SR-2": "Supply chain risk management plan",
    "SR-3": "Supply chain controls and processes",
    "SR-4": "Provenance",
    "SR-5": "Acquisition strategies, tools, and methods",
    "SR-6": "Supplier assessments and reviews",
    "SR-7": "Supply chain operations security",
    "SR-8": "Notification agreements",
    "SR-9": "Tamper resistance and detection",
    "SR-10": "Inspection of systems or components",
    "SR-11": "Component authenticity",
    "SR-12": "Component disposal",
}

for ctrl_id, summ in SR_BASE_DEFS.items():
    if ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document supply chain risk management procedures",
                "Assess and monitor suppliers",
                "Review and update annually",
            ],
            "console_path": "GRC Platform > Supply Chain Risk Management",
            "recommended_reading": [
                f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures",
                "NIST SP 800-161: SCRM Practices",
            ],
            "evidence_types": ["vendor_assessments", "policy_document"],
        }

# ============================================================
# Now handle ALL enhancement controls that aren't yet defined
# by generating reasonable entries based on family and base control
# ============================================================

# Collect all control IDs that still need entries
missing = [c for c in all_controls if c not in CONTROLS]
print(f"Controls defined so far: {len(CONTROLS)}")
print(f"Controls still needed: {len(missing)}")

# Enhancement descriptions for remaining controls
# We'll generate based on the family context
FAMILY_CONTEXT = {
    "AC": {"category": "technical", "domain": "Access Control", "console": "IAM > Access Control"},
    "AT": {
        "category": "administrative",
        "domain": "Awareness and Training",
        "console": "Training Platform",
    },
    "AU": {
        "category": "operational",
        "domain": "Audit and Accountability",
        "console": "SIEM > Audit",
    },
    "CA": {
        "category": "operational",
        "domain": "Assessment and Authorization",
        "console": "GRC Platform",
    },
    "CM": {
        "category": "operational",
        "domain": "Configuration Management",
        "console": "Configuration Management",
    },
    "CP": {
        "category": "operational",
        "domain": "Contingency Planning",
        "console": "Business Continuity",
    },
    "IA": {
        "category": "technical",
        "domain": "Identification and Authentication",
        "console": "Identity Provider",
    },
    "IR": {
        "category": "operational",
        "domain": "Incident Response",
        "console": "Incident Response",
    },
    "MA": {"category": "operational", "domain": "Maintenance", "console": "Maintenance Management"},
    "MP": {"category": "operational", "domain": "Media Protection", "console": "Media Protection"},
    "PE": {
        "category": "physical",
        "domain": "Physical and Environmental Protection",
        "console": "Facilities Management",
    },
    "PL": {
        "category": "administrative",
        "domain": "Planning",
        "console": "GRC Platform > Planning",
    },
    "PM": {
        "category": "administrative",
        "domain": "Program Management",
        "console": "GRC Platform > Program Management",
    },
    "PS": {
        "category": "administrative",
        "domain": "Personnel Security",
        "console": "HR System > Personnel Security",
    },
    "PT": {
        "category": "administrative",
        "domain": "PII Processing and Transparency",
        "console": "Privacy Portal",
    },
    "RA": {
        "category": "operational",
        "domain": "Risk Assessment",
        "console": "GRC Platform > Risk Assessment",
    },
    "SA": {
        "category": "operational",
        "domain": "System and Services Acquisition",
        "console": "GRC Platform > Acquisition",
    },
    "SC": {
        "category": "technical",
        "domain": "System and Communications Protection",
        "console": "Network > Security",
    },
    "SI": {
        "category": "technical",
        "domain": "System and Information Integrity",
        "console": "Security Center",
    },
    "SR": {
        "category": "operational",
        "domain": "Supply Chain Risk Management",
        "console": "Supply Chain Management",
    },
}

for ctrl_id in missing:
    family = ctrl_id.split("-")[0]
    ctx = FAMILY_CONTEXT.get(
        family, {"category": "operational", "domain": family, "console": "GRC Platform"}
    )
    base = base_control(ctrl_id)
    enh = enhancement_num(ctrl_id)

    # Get parent summary if available
    parent_summ = CONTROLS.get(base, {}).get("summary", ctx["domain"] + " control")

    if enh:
        summ = f"Enhancement {enh} for {base}"
        steps = [
            f"Implement enhancement {enh} requirements for {base}",
            f"Configure additional {ctx['domain'].lower()} controls",
            "Verify enhancement effectiveness through testing",
            "Document implementation and review annually",
        ]
    else:
        summ = f"{ctx['domain']} control {ctrl_id}"
        steps = [
            f"Implement {ctx['domain'].lower()} requirements for {ctrl_id}",
            "Configure supporting controls and monitoring",
            "Verify effectiveness through testing",
            "Document implementation and review annually",
        ]

    evidence = {
        "technical": ["config_snapshots"],
        "administrative": ["policy_document"],
        "operational": ["config_snapshots", "process_records"],
        "physical": ["physical_inspection_records"],
    }.get(ctx["category"], ["config_snapshots"])

    CONTROLS[ctrl_id] = {
        "summary": summ,
        "remediation_steps": steps,
        "console_path": ctx["console"],
        "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
        "evidence_types": evidence,
    }

# ============================================================
# Add specific detail for well-known enhancements we haven't covered
# ============================================================

# PE enhancements
PE_ENH_NAMES = {
    "PE-2(1)": "Access by position or role",
    "PE-2(2)": "Two forms of identification",
    "PE-2(3)": "Restrict unescorted access",
    "PE-3(1)": "System access",
    "PE-3(2)": "Facility and systems",
    "PE-3(3)": "Continuous guards",
    "PE-3(4)": "Lockable casings",
    "PE-3(5)": "Tamper protection",
    "PE-3(6)": "Facility penetration testing",
    "PE-3(7)": "Physical barriers",
    "PE-3(8)": "Access control vestibules",
    "PE-4(1)": "Electromagnetic emanation guards",
    "PE-5(1)": "Access to output by authorized individuals",
    "PE-5(2)": "Link to individual identity",
    "PE-5(3)": "Marking output devices",
    "PE-6(1)": "Intrusion alarms and surveillance",
    "PE-6(2)": "Automated intrusion recognition",
    "PE-6(3)": "Video surveillance",
    "PE-6(4)": "Monitoring physical access to systems",
    "PE-8(1)": "Automated records maintenance",
    "PE-8(2)": "Physical access records",
    "PE-8(3)": "Limit release of visitor access records",
    "PE-9(1)": "Redundant cabling",
    "PE-9(2)": "Automatic voltage controls",
    "PE-10(1)": "Accidental and unauthorized activation safeguards",
    "PE-11(1)": "Alternate power supply — self-contained",
    "PE-11(2)": "Alternate power supply — long-term self-sufficient",
    "PE-12(1)": "Essential missions and business functions",
    "PE-13(1)": "Detection systems — automatic activation and notification",
    "PE-13(2)": "Suppression systems — automatic activation and notification",
    "PE-13(3)": "Automatic fire suppression",
    "PE-13(4)": "Inspections",
    "PE-14(1)": "Automatic controls",
    "PE-14(2)": "Monitoring with alarms and notifications",
    "PE-15(1)": "Automation support",
    "PE-17(1)": "Alternate work site monitoring",
    "PE-18(1)": "Facility site",
    "PE-19(1)": "National EMSEC/TEMPEST policies and procedures",  # just PE-19 already covered
    "PE-23(1)": "Component installation and removal",
}

for ctrl_id, summ in PE_ENH_NAMES.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
        CONTROLS[ctrl_id]["remediation_steps"] = [
            f"Implement {summ.lower()}",
            "Configure facility security controls",
            "Verify effectiveness through physical inspection",
            "Document and review annually",
        ]

# MA enhancements
MA_ENH = {
    "MA-2(1)": "Record content of maintenance activities",
    "MA-2(2)": "Automated maintenance activities",
    "MA-3(1)": "Inspect maintenance tools",
    "MA-3(2)": "Inspect maintenance media",
    "MA-3(3)": "Prevent unauthorized removal of maintenance equipment",
    "MA-3(4)": "Restricted tool use",
    "MA-3(5)": "Execution with privilege",
    "MA-3(6)": "Software updates and patches for maintenance tools",
    "MA-4(1)": "Audit and review of nonlocal maintenance sessions",
    "MA-4(2)": "Document nonlocal maintenance activities",
    "MA-4(3)": "Comparable security for nonlocal maintenance",
    "MA-4(4)": "Authentication and separation of maintenance sessions",
    "MA-4(5)": "Approvals and notifications for nonlocal maintenance",
    "MA-4(6)": "Cryptographic protection for nonlocal maintenance",
    "MA-4(7)": "Disconnect verification for nonlocal maintenance",
    "MA-5(1)": "Individuals without appropriate access",
    "MA-5(2)": "Nonsystem maintenance using alternate procedures",
    "MA-5(3)": "Citizenship requirements for classified maintenance",
    "MA-5(4)": "Foreign nationals",
    "MA-5(5)": "Non-system maintenance",
    "MA-6(1)": "Preventive maintenance",
    "MA-6(2)": "Predictive maintenance",
    "MA-6(3)": "Automated support for predictive maintenance",
    "MA-7(1)": "Field maintenance accountability",
    "MA-7(2)": "Controlled maintenance areas",
}

for ctrl_id, summ in MA_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
        CONTROLS[ctrl_id]["remediation_steps"] = [
            f"Implement {summ.lower()}",
            "Document maintenance procedures",
            "Verify through inspection",
            "Review annually",
        ]
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document maintenance procedures",
                "Verify through inspection",
                "Review annually",
            ],
            "console_path": "Maintenance Management",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["maintenance_records"],
        }

# MP enhancements
MP_ENH = {
    "MP-2(1)": "Automated restricted access",
    "MP-2(2)": "Cryptographic protection of media",
    "MP-3(1)": "Automated marking",
    "MP-3(2)": "Removable media marking",
    "MP-4(1)": "Cryptographic protection",
    "MP-4(2)": "Automated restricted access",
    "MP-5(1)": "Protection outside of controlled areas",
    "MP-5(2)": "Documentation of activities",
    "MP-5(3)": "Custodians",
    "MP-5(4)": "Cryptographic protection during transport",
    "MP-6(1)": "Review, approve, track, and verify media sanitization",
    "MP-6(2)": "Equipment testing",
    "MP-6(3)": "Nondestructive techniques",
    "MP-6(4)": "Controlled unclassified information",
    "MP-6(5)": "Classified information",
    "MP-6(6)": "Media destruction",
    "MP-6(7)": "Dual authorization",
    "MP-6(8)": "Remote purging or wiping",
    "MP-7(1)": "Prohibit use without owner",
    "MP-7(2)": "Prohibit use of sanitization-resistant media",
    "MP-8(1)": "Documentation of process",
    "MP-8(2)": "Equipment testing",
    "MP-8(3)": "Controlled unclassified information",
    "MP-8(4)": "Classified information",
}

for ctrl_id, summ in MP_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document media protection procedures",
                "Verify through inspection",
                "Review annually",
            ],
            "console_path": "Media Protection",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["config_snapshots"],
        }

# PL enhancements
PL_ENH = {
    "PL-2(1)": "Concept of operations (withdrawn)",
    "PL-2(2)": "Functional architecture (withdrawn)",
    "PL-2(3)": "Plan and coordinate with other organizational entities",
    "PL-4(1)": "Social media and external site restrictions",
    "PL-7(1)": "Security and privacy concepts of operations",
    "PL-7(2)": "Security and privacy concept of operations updates",
    "PL-8(1)": "Defense in depth",
    "PL-8(2)": "Supplier diversity",
}

for ctrl_id, summ in PL_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                "This control has been withdrawn"
                if "withdrawn" in summ.lower()
                else f"Implement {summ.lower()}",
                "Verify replacement control is implemented"
                if "withdrawn" in summ.lower()
                else "Document planning requirements",
                "Review annually",
                "Track compliance",
            ],
            "console_path": "GRC Platform > Planning",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["policy_document"],
        }

# PM enhancements
PM_ENH = {
    "PM-5(1)": "Inventory of PII",
    "PM-7(1)": "Offloading",
    "PM-11(1)": "Ongoing authorization",
    "PM-14(1)": "Testing, training, and monitoring program",
    "PM-16(1)": "Automated threat awareness",
    "PM-25(1)": "Minimization of PII in testing",
    "PM-30(1)": "Supply chain risk management plan updates",
    "PM-31(1)": "Continuous monitoring work programs",
}

for ctrl_id, summ in PM_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document program management details",
                "Review annually",
                "Track compliance",
            ],
            "console_path": "GRC Platform > Program Management",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["policy_document"],
        }

# PS enhancements
PS_ENH = {
    "PS-3(1)": "Classified information screening",
    "PS-3(2)": "Formal indoctrination",
    "PS-3(3)": "Information requiring special protection",
    "PS-3(4)": "Citizenship requirements",
    "PS-4(1)": "Post-employment requirements",
    "PS-4(2)": "Automated actions on termination",
    "PS-5(1)": "Access restriction changes",
    "PS-5(2)": "Automated notification",
    "PS-5(3)": "Automated actions on transfer",
    "PS-6(1)": "Information requiring special protection",
    "PS-6(2)": "Classified information requiring special protection",
    "PS-6(3)": "Post-employment requirements",
    "PS-7(1)": "Documentation of external personnel",
    "PS-9(1)": "Classified information positions",
    "PS-9(2)": "Position sensitivity levels",
}

for ctrl_id, summ in PS_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document personnel security procedures",
                "Review annually",
                "Track compliance",
            ],
            "console_path": "HR System > Personnel Security",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["personnel_records"],
        }

# PT enhancements
PT_ENH = {
    "PT-2(1)": "Data tagging for authority to process PII",
    "PT-2(2)": "Automation of authority tracking",
    "PT-3(1)": "Data tagging for PII processing purposes",
    "PT-3(2)": "Automation of purpose tracking",
    "PT-4(1)": "Tailored consent",
    "PT-4(2)": "Just-in-time consent",
    "PT-4(3)": "Revocation of consent",
    "PT-5(1)": "Just-in-time notice",
    "PT-5(2)": "Privacy act statements",
    "PT-6(1)": "Routine uses",
    "PT-6(2)": "Exemption rules",
    "PT-7(1)": "Social security numbers",
    "PT-7(2)": "First amendment information",
    "PT-8(1)": "Prohibition on match with non-federal records",
    "PT-8(2)": "Review by matching programs officials",
    "PT-8(3)": "Data integrity board",
}

for ctrl_id, summ in PT_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document privacy requirements",
                "Review annually",
                "Track compliance",
            ],
            "console_path": "Privacy Portal > PII Management",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["privacy_records"],
        }

# RA enhancements
RA_ENH = {
    "RA-2(1)": "Impact-level prioritization",
    "RA-3(1)": "Supply chain risk assessment",
    "RA-3(2)": "Use of threat intelligence for risk assessment",
    "RA-3(3)": "Dynamic threat environment",
    "RA-3(4)": "Predictive cyber analytics",
    "RA-5(1)": "Update vulnerabilities to be scanned (withdrawn)",
    "RA-5(2)": "Update vulnerability scanning tools and signatures",
    "RA-5(3)": "Breadth and depth of vulnerability scanning coverage",
    "RA-5(4)": "Discoverable information",
    "RA-5(5)": "Privileged access for vulnerability scanning",
    "RA-5(6)": "Automated trend analysis for vulnerability scanning",
    "RA-5(7)": "Automated detection and notification of unauthorized components (withdrawn)",
    "RA-5(8)": "Review historic audit logs for vulnerability scanning",
    "RA-5(9)": "Penetration testing and analysis",
    "RA-5(10)": "Correlate vulnerability scanning information",
    "RA-5(11)": "Public disclosure program",
    "RA-7(1)": "Risk response documentation",
    "RA-9(1)": "Impact analyses for criticality analysis",
    "RA-9(2)": "Supply chain criticality analysis",
    "RA-9(3)": "Identification of critical components",
    "RA-9(4)": "Business continuity criticality analysis",
    "RA-10(1)": "Threat hunting team resources",
}

for ctrl_id, summ in RA_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                "This control has been withdrawn"
                if "withdrawn" in summ.lower()
                else f"Implement {summ.lower()}",
                "Verify replacement control"
                if "withdrawn" in summ.lower()
                else "Configure risk assessment tools",
                "Review annually",
                "Track compliance",
            ],
            "console_path": "GRC Platform > Risk Assessment"
            if "RA-5" not in ctrl_id
            else "Qualys > Scans | Tenable > Dashboard",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["vulnerability_scans"] if "RA-5" in ctrl_id else ["risk_assessment"],
        }

# SR enhancements
SR_ENH = {
    "SR-2(1)": "Establish SCRM team",
    "SR-3(1)": "Diverse supply base",
    "SR-3(2)": "Limit harm from supply chain compromise",
    "SR-3(3)": "Sub-tier flow down",
    "SR-4(1)": "Identity of provenance",
    "SR-4(2)": "Track and trace",
    "SR-4(3)": "Validate as genuine and not altered",
    "SR-4(4)": "Supply chain integrity — pedigree",
    "SR-5(1)": "Adequate supply",
    "SR-5(2)": "Assessments prior to selection",
    "SR-6(1)": "Testing and analysis of supply chain elements",
    "SR-9(1)": "Multiple stages of system development life cycle",
    "SR-10(1)": "Inspection of systems — periodic unannounced",
    "SR-11(1)": "Anti-counterfeit training",
    "SR-11(2)": "Configuration control for component service and repair",
    "SR-11(3)": "Anti-counterfeit scanning",
    "SR-12(1)": "Disposal records",
}

for ctrl_id, summ in SR_ENH.items():
    if ctrl_id in CONTROLS and CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
        CONTROLS[ctrl_id]["summary"] = summ
    elif ctrl_id not in CONTROLS:
        CONTROLS[ctrl_id] = {
            "summary": summ,
            "remediation_steps": [
                f"Implement {summ.lower()}",
                "Document supply chain procedures",
                "Review annually",
                "Track compliance",
            ],
            "console_path": "Supply Chain Management",
            "recommended_reading": [
                f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures",
                "NIST SP 800-161: SCRM Practices",
            ],
            "evidence_types": ["vendor_assessments"],
        }

# Update specific enhancement summaries for SA, SC, SI
# SA enhancements
SA_ENH_SUMMS = {}
for i in range(1, 8):
    SA_ENH_SUMMS[f"SA-10({i})"] = {
        1: "Software/firmware integrity verification",
        2: "Alternative configuration management processes",
        3: "Hardware integrity verification",
        4: "Trusted generation",
        5: "Mapping integrity for version control",
        6: "Trusted distribution",
        7: "Security and privacy representatives",
    }[i]
for i in range(1, 10):
    SA_ENH_SUMMS[f"SA-11({i})"] = {
        1: "Static code analysis",
        2: "Threat modeling and vulnerability analysis",
        3: "Independent verification of assessment plans",
        4: "Manual code reviews",
        5: "Penetration testing",
        6: "Attack surface reviews",
        7: "Verify scope of testing",
        8: "Dynamic code analysis",
        9: "Interactive application security testing",
    }[i]

# SA-8 has many enhancements (1-33)
for i in range(1, 34):
    key = f"SA-8({i})"
    if key not in SA_ENH_SUMMS:
        SA_ENH_SUMMS[key] = f"Security engineering principle {i}"

# SA-4 enhancements
for i in range(1, 13):
    key = f"SA-4({i})"
    names = {
        1: "Functional properties of controls",
        2: "Design and implementation for controls",
        3: "Development methods, techniques, and practices",
        4: "Assignment of components to systems (withdrawn)",
        5: "System, component, and service configurations",
        6: "Use of information assurance products",
        7: "NIAP-approved protection profiles",
        8: "Continuous monitoring plan for controls",
        9: "Functions, ports, protocols, and services in use",
        10: "Use of approved PIV products",
        11: "System of records",
        12: "Data ownership",
    }
    SA_ENH_SUMMS[key] = names.get(i, f"Acquisition requirement {i}")

for i in range(1, 6):
    SA_ENH_SUMMS[f"SA-5({i})"] = {
        1: "Functional properties of security controls documentation",
        2: "Security-relevant external system interfaces",
        3: "High-level design documentation",
        4: "Low-level design documentation",
        5: "Source code documentation",
    }[i]

# SA-9 enhancements
for i in range(1, 9):
    SA_ENH_SUMMS[f"SA-9({i})"] = {
        1: "Risk assessments and organizational approvals",
        2: "Identification of functions, ports, protocols, and services",
        3: "Establish and maintain trust relationship with providers",
        4: "Consistent interests of consumers and providers",
        5: "Processing, storage, and service location",
        6: "Organization-controlled cryptographic keys",
        7: "Organization-controlled integrity checking",
        8: "Processing and storage location — US jurisdiction",
    }[i]

for i in range(1, 13):
    key = f"SA-15({i})"
    names = {
        1: "Quality metrics",
        2: "Security and privacy tracking tools",
        3: "Criticality analysis",
        4: "Threat modeling and vulnerability analysis",
        5: "Attack surface reduction",
        6: "Continuous improvement",
        7: "Automated vulnerability analysis",
        8: "Reuse of threat and vulnerability information",
        9: "Use of live data (withdrawn)",
        10: "Incident response plan",
        11: "Archive system or component",
        12: "Minimize personally identifiable information",
    }
    if i in names:
        SA_ENH_SUMMS[key] = names[i]

for i in range(1, 10):
    key = f"SA-17({i})"
    names = {
        1: "Formal policy model",
        2: "Security-relevant components",
        3: "Formal correspondence",
        4: "Informal correspondence",
        5: "Conceptually simple design",
        6: "Structure for testing",
        7: "Structure for least privilege",
        8: "Orchestration",
        9: "Design diversity",
    }
    if i in names:
        SA_ENH_SUMMS[key] = names[i]

# SA-2, SA-3 enhancements
SA_ENH_SUMMS["SA-2(1)"] = "Security resources in capital planning"
SA_ENH_SUMMS["SA-2(2)"] = "Security resources in programming and budgeting"
SA_ENH_SUMMS["SA-3(1)"] = "Manage preproduction environment"
SA_ENH_SUMMS["SA-3(2)"] = "Use of live or operational data"
SA_ENH_SUMMS["SA-3(3)"] = "Technology refresh"

# SA-12 enhancements (withdrawn but in source YAML)
for i in range(1, 16):
    SA_ENH_SUMMS[f"SA-12({i})"] = (
        f"Supply chain protection enhancement {i} (withdrawn - see SR family)"
    )

for ctrl_id, summ in SA_ENH_SUMMS.items():
    if ctrl_id in CONTROLS:
        if CONTROLS[ctrl_id]["summary"].startswith("Enhancement") or CONTROLS[ctrl_id][
            "summary"
        ].startswith("Supply chain"):
            CONTROLS[ctrl_id]["summary"] = summ
            if "withdrawn" not in summ.lower():
                CONTROLS[ctrl_id]["remediation_steps"] = [
                    f"Implement {summ.lower()}",
                    "Configure in development and acquisition processes",
                    "Verify through security testing",
                    "Document and review annually",
                ]

# SC enhancements
SC_ENH_SUMMS = {}
# SC-7 has many enhancements (1-29)
for i in range(1, 30):
    names = {
        1: "Physically separated subnetworks",
        2: "Public access",
        3: "Access points",
        4: "External telecommunications services",
        5: "Deny by default/allow by exception",
        6: "Response to recognized failures (withdrawn)",
        7: "Split tunneling for remote devices",
        8: "Route traffic to authenticated proxy servers",
        9: "Restrict threatening outgoing traffic",
        10: "Prevent exfiltration",
        11: "Restrict incoming communications traffic",
        12: "Host-based protection",
        13: "Isolation of security tools",
        14: "Protection against unauthorized physical connections",
        15: "Networked privileged accesses",
        16: "Prevent discovery of system components",
        17: "Automated enforcement of protocol formats",
        18: "Fail secure",
        19: "Block communication from non-organizationally configured hosts",
        20: "Dynamic isolation and segregation",
        21: "Isolation of system components",
        22: "Separate subnets for connecting to different security domains",
        23: "Disable sender feedback on protocol validation failure",
        24: "Personally identifiable information",
        25: "Connections in public environments",
        26: "Classified national security system connections",
        27: "Unclassified non-national security system connections",
        28: "Connections to public networks",
        29: "Separate subnets to isolate functions",
    }
    if i in names:
        SC_ENH_SUMMS[f"SC-7({i})"] = names[i]

# SC-28 enhancements
SC_ENH_SUMMS["SC-28(1)"] = "Cryptographic protection of information at rest"
SC_ENH_SUMMS["SC-28(2)"] = "Offline storage of information at rest"
SC_ENH_SUMMS["SC-28(3)"] = "Cryptographic keys of information at rest"

# SC-8 enhancements
SC_ENH_SUMMS["SC-8(1)"] = "Cryptographic protection of transmission"
SC_ENH_SUMMS["SC-8(2)"] = "Pre/post transmission handling"
SC_ENH_SUMMS["SC-8(3)"] = "Cryptographic protection for message externals"
SC_ENH_SUMMS["SC-8(4)"] = "Conceal or randomize communications"
SC_ENH_SUMMS["SC-8(5)"] = "Protected distribution system"

# SC-12 enhancements
for i in range(1, 7):
    names = {
        1: "Availability of key management",
        2: "Symmetric keys",
        3: "Asymmetric keys",
        4: "PKI certificates (withdrawn)",
        5: "PKI certificates (withdrawn)",
        6: "Physical control of keys",
    }
    SC_ENH_SUMMS[f"SC-12({i})"] = names.get(i, f"Key management enhancement {i}")

# SC-13 enhancements
for i in range(1, 5):
    names = {
        1: "FIPS-validated cryptography",
        2: "NSA-approved cryptography",
        3: "Individuals without formal access",
        4: "Digital signatures",
    }
    SC_ENH_SUMMS[f"SC-13({i})"] = names.get(i, f"Cryptographic protection enhancement {i}")

# Additional SC enhancements
SC_MISC = {
    "SC-2(1)": "Interfaces for non-privileged users",
    "SC-2(2)": "Disassociability",
    "SC-3(1)": "Hardware separation",
    "SC-3(2)": "Access and flow control",
    "SC-3(3)": "Minimize nonsecurity functionality",
    "SC-3(4)": "Module coupling and cohesiveness",
    "SC-3(5)": "Layered structures",
    "SC-4(1)": "Security levels",
    "SC-4(2)": "Periods processing",
    "SC-5(1)": "Restrict ability to attack other systems",
    "SC-5(2)": "Capacity, bandwidth, and redundancy",
    "SC-5(3)": "Detection and monitoring",
    "SC-10(1)": "RPC timeout",
    "SC-16(1)": "Integrity verification",
    "SC-16(2)": "Anti-spoofing mechanisms",
    "SC-16(3)": "Cryptographic mechanisms for attributes",
    "SC-17(1)": "Certificate status mechanism",
    "SC-18(1)": "Identify unacceptable mobile code",
    "SC-18(2)": "Acquisition, development, and use",
    "SC-18(3)": "Prevent downloading and execution",
    "SC-18(4)": "Prevent automatic execution",
    "SC-18(5)": "Allow execution only in confined environments",
    "SC-23(1)": "Invalidate session identifiers at logout",
    "SC-23(2)": "User-initiated logouts and message displays (withdrawn)",
    "SC-23(3)": "Unique session identifiers with randomization",
    "SC-23(4)": "Unique session identifiers",
    "SC-23(5)": "Allowed certificate authorities",
    "SC-26(1)": "Detection of malicious code",
    "SC-29(1)": "Virtualization techniques",
    "SC-31(1)": "Test covert channels for exploitability",
    "SC-31(2)": "Maximum bandwidth",
    "SC-31(3)": "Measure bandwidth in operational environments",
    "SC-36(1)": "Polling techniques",
    "SC-36(2)": "Synchronization",
    "SC-39(1)": "Hardware separation",
    "SC-39(2)": "Separate execution domain per thread",
    "SC-45(1)": "Synchronization with authoritative time source",
    "SC-45(2)": "Secondary authoritative time source",
}

SC_ENH_SUMMS.update(SC_MISC)

for ctrl_id, summ in SC_ENH_SUMMS.items():
    if ctrl_id in CONTROLS:
        if CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
            CONTROLS[ctrl_id]["summary"] = summ
            if "withdrawn" not in summ.lower():
                CONTROLS[ctrl_id]["remediation_steps"] = [
                    f"Implement {summ.lower()}",
                    "Configure in network and system security settings",
                    "Verify through security testing",
                    "Document and review annually",
                ]

# SI enhancements
SI_ENH_SUMMS = {}
# SI-2 enhancements
for i in range(1, 7):
    names = {
        1: "Central management of flaw remediation",
        2: "Automated flaw remediation status",
        3: "Time to remediate flaws and benchmarks",
        4: "Automated patch management tools",
        5: "Automatic software and firmware updates",
        6: "Removal of previous versions of software and firmware",
    }
    SI_ENH_SUMMS[f"SI-2({i})"] = names.get(i, f"Flaw remediation enhancement {i}")

# SI-3 enhancements
for i in range(1, 11):
    names = {
        1: "Central management of malicious code protection",
        2: "Automatic updates",
        3: "Non-privileged users (withdrawn)",
        4: "Updates only by privileged users",
        5: "Portable storage devices (withdrawn)",
        6: "Testing and verification",
        7: "Nonsignature-based detection",
        8: "Detect unauthorized commands",
        9: "Authenticate remote commands",
        10: "Malicious code analysis",
    }
    SI_ENH_SUMMS[f"SI-3({i})"] = names.get(i, f"Malicious code protection enhancement {i}")

# SI-4 enhancements
for i in range(1, 26):
    names = {
        1: "System-wide intrusion detection",
        2: "Automated analysis and integration",
        3: "Automated tool and mechanism integration",
        4: "Inbound and outbound communications traffic",
        5: "System-generated alerts",
        6: "Restrict non-privileged users (withdrawn)",
        7: "Automated response to suspicious events",
        8: "Protection of monitoring information (withdrawn)",
        9: "Testing of monitoring tools and mechanisms",
        10: "Visibility of encrypted communications",
        11: "Analyze communications traffic anomalies",
        12: "Automated organization-generated alerts",
        13: "Analyze traffic and event patterns",
        14: "Wireless intrusion detection",
        15: "Wireless to wired communications",
        16: "Correlate monitoring information",
        17: "Integrated situational awareness",
        18: "Analyze traffic and covert exfiltration",
        19: "Risk for individuals",
        20: "Privileged users",
        21: "Probationary periods",
        22: "Unauthorized network services",
        23: "Host-based devices",
        24: "Indicators of compromise",
        25: "Optimize network traffic analysis",
    }
    if i in names:
        SI_ENH_SUMMS[f"SI-4({i})"] = names[i]

# SI-5(1)
SI_ENH_SUMMS["SI-5(1)"] = "Automated alerts and advisories"

# SI-6 enhancements
for i in range(1, 4):
    names = {
        1: "Notification of failed security tests (withdrawn)",
        2: "Automation support for distributed testing",
        3: "Report verification results",
    }
    SI_ENH_SUMMS[f"SI-6({i})"] = names.get(i, f"Verification enhancement {i}")

# SI-7 enhancements
for i in range(1, 18):
    names = {
        1: "Integrity checks",
        2: "Automated notifications of integrity violations",
        3: "Centrally managed integrity tools",
        4: "Tamper-evident packaging (withdrawn)",
        5: "Automated response to integrity violations",
        6: "Cryptographic protection",
        7: "Integration of detection and response",
        8: "Auditing capability for significant events",
        9: "Verify boot process",
        10: "Protection of boot firmware",
        11: "Confined environments with limited privileges",
        12: "Integrity verification",
        13: "Code execution in protected environments",
        14: "Binary or machine executable code",
        15: "Code authentication",
        16: "Time limit on process execution without supervision",
        17: "Runtime application self-protection",
    }
    if i in names:
        SI_ENH_SUMMS[f"SI-7({i})"] = names[i]

# SI-10 enhancements
for i in range(1, 7):
    names = {
        1: "Manual override capability",
        2: "Review and resolve errors",
        3: "Predictive and reactive validation",
        4: "Timing interactions",
        5: "Restrict inputs to trusted sources",
        6: "Injection prevention",
    }
    SI_ENH_SUMMS[f"SI-10({i})"] = names.get(i, f"Input validation enhancement {i}")

# SI-12 enhancements
for i in range(1, 4):
    names = {
        1: "Limit personally identifiable information elements",
        2: "Minimize PII in testing",
        3: "Information disposal",
    }
    SI_ENH_SUMMS[f"SI-12({i})"] = names.get(i, f"Information management enhancement {i}")

# SI-16 enhancements
for i in range(1, 4):
    SI_ENH_SUMMS[f"SI-16({i})"] = {
        1: "Stack protection",
        2: "Heap protection",
        3: "Code segment protection",
    }.get(i, f"Memory protection enhancement {i}")

# SI-18 enhancements
for i in range(1, 6):
    names = {
        1: "Automation support",
        2: "Data tags",
        3: "Collection",
        4: "Individual requests",
        5: "Notice of correction or deletion",
    }
    SI_ENH_SUMMS[f"SI-18({i})"] = names.get(i, f"PII quality enhancement {i}")

# SI-19 enhancements
for i in range(1, 9):
    names = {
        1: "Collection",
        2: "Archiving",
        3: "Release",
        4: "Removal, masking, or alteration of direct identifiers",
        5: "Statistical disclosure control",
        6: "Differential privacy",
        7: "Validated algorithms and software",
        8: "Motivated intruder",
    }
    SI_ENH_SUMMS[f"SI-19({i})"] = names.get(i, f"De-identification enhancement {i}")

# SI-20 enhancements
SI_ENH_SUMMS["SI-20(1)"] = "Automated tainting"
SI_ENH_SUMMS["SI-20(2)"] = "Inspection of output and input"
SI_ENH_SUMMS["SI-21(1)"] = "Automated information refresh"
SI_ENH_SUMMS["SI-22(1)"] = "Information diversity — automation"
SI_ENH_SUMMS["SI-23(1)"] = "Information fragmentation — automation"

for ctrl_id, summ in SI_ENH_SUMMS.items():
    if ctrl_id in CONTROLS:
        if CONTROLS[ctrl_id]["summary"].startswith("Enhancement"):
            CONTROLS[ctrl_id]["summary"] = summ
            if "withdrawn" not in summ.lower():
                CONTROLS[ctrl_id]["remediation_steps"] = [
                    f"Implement {summ.lower()}",
                    "Configure in security and monitoring tools",
                    "Verify through testing",
                    "Document and review annually",
                ]

# ============================================================
# Build the final YAML structure
# ============================================================


# Sort controls by family and number for clean output
def sort_key(ctrl_id):
    """Sort controls: AC-1, AC-2, AC-2(1), AC-2(2), ..., AC-3, etc."""
    base = ctrl_id.split("(")[0] if "(" in ctrl_id else ctrl_id
    parts = base.split("-")
    family = parts[0]
    num = int(parts[1])
    enh = int(ctrl_id.split("(")[1].rstrip(")")) if "(" in ctrl_id else 0
    return (family, num, enh)


sorted_controls = sorted(all_controls, key=sort_key)

# Build output dict preserving order
output = {"controls": {}}
for ctrl_id in sorted_controls:
    ctrl = CONTROLS.get(ctrl_id)
    if ctrl is None:
        # Should not happen but safety net
        family = ctrl_id.split("-")[0]
        ctrl = {
            "summary": f"NIST 800-53 Rev 5 control {ctrl_id}",
            "remediation_steps": [
                f"Implement {ctrl_id} requirements",
                "Document implementation",
                "Review annually",
                "Track compliance",
            ],
            "console_path": "GRC Platform",
            "recommended_reading": [f"NIST SP 800-53A Rev 5: {ctrl_id} Assessment Procedures"],
            "evidence_types": ["config_snapshots"],
        }

    assertion = ASSERTION_MAP.get(ctrl_id)

    entry = {
        "summary": ctrl["summary"],
        "remediation_steps": ctrl["remediation_steps"],
        "console_path": ctrl["console_path"],
        "recommended_reading": ctrl["recommended_reading"],
        "evidence_types": ctrl["evidence_types"],
        "assertion_name": assertion,
    }
    output["controls"][ctrl_id] = entry

# Verify count
print(f"Final control count: {len(output['controls'])}")

# Write YAML


class QuotedStr(str):
    pass


def quoted_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')


yaml.add_representer(QuotedStr, quoted_representer)


# Custom dumper that handles None as null
class NullDumper(yaml.SafeDumper):
    pass


def represent_none(dumper, _):
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")


NullDumper.add_representer(type(None), represent_none)

output_path = ROOT / "warlock" / "frameworks" / "remediation" / "nist_800_53.yaml"
with open(output_path, "w") as f:
    yaml.dump(
        output,
        f,
        Dumper=NullDumper,
        default_flow_style=False,
        sort_keys=False,
        width=120,
        allow_unicode=True,
    )

print(f"Written to {output_path}")
