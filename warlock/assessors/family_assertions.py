"""Family-level default assertions for controls without specific assertion bindings.

These provide a reasonable automated assessment based on whether ANY evidence
from the control family's domain exists and indicates compliance. They are
less precise than specific assertions but ensure every control gets a verdict.

Design principles:
- Fail-closed: no evidence → non_compliant (CLAUDE.md: "Fail-closed security")
- Single responsibility: each family function checks one evidence domain
- Registered with the singleton engine so they participate in normal Tier 1 assessment
- Never overwrite existing, more-specific bindings (caller's responsibility)

Naming convention: family_{family_lower}_default
  e.g. family_ac_default, family_at_default, family_hipaa_308_default
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from warlock.assessors.engine import engine as _engine

if TYPE_CHECKING:
    from warlock.assessors.engine import AssertionEngine

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Evidence helpers — shared across multiple family assertions
# ---------------------------------------------------------------------------

def _any_true(detail: dict[str, Any], *keys: str) -> bool:
    """Return True if any of the given keys in detail is truthy."""
    return any(detail.get(k) for k in keys)


def _status_ok(detail: dict[str, Any]) -> bool:
    """Return True if a generic status field signals passing/active state."""
    status = str(detail.get("status") or detail.get("state") or "").lower()
    return status in ("active", "enabled", "compliant", "completed", "ok", "pass", "passed", "normal")


def _status_bad(detail: dict[str, Any]) -> bool:
    """Return True if a generic status field signals a failure state."""
    status = str(detail.get("status") or detail.get("state") or "").lower()
    return status in (
        "non_compliant", "noncompliant", "failed", "fail", "error",
        "disabled", "inactive", "expired", "overdue",
    )


def _issues_present(detail: dict[str, Any]) -> bool:
    """Return True if detail contains a non-empty issues list."""
    issues = detail.get("issues", [])
    return isinstance(issues, list) and len(issues) > 0


def _compliant_flag(detail: dict[str, Any]) -> bool | None:
    """Return the value of an explicit compliant/is_compliant flag, or None."""
    for key in ("compliant", "is_compliant", "passed", "is_passing"):
        val = detail.get(key)
        if val is not None:
            return bool(val)
    return None


def _eval_domain(
    detail: dict[str, Any],
    domain_keys: list[str],
    family_name: str,
) -> tuple[bool, list[str]]:
    """Generic domain evaluator used by most family assertions.

    Logic:
    1. If explicit compliant flag is present, trust it.
    2. If issues list is non-empty, fail.
    3. If status field is bad, fail.
    4. If status field is good, pass.
    5. If any domain_keys are present in detail, pass (evidence exists).
    6. Otherwise: no evidence → fail closed.
    """
    flag = _compliant_flag(detail)
    if flag is not None:
        if flag:
            return True, []
        return False, [f"{family_name} compliance flag is false"]

    if _issues_present(detail):
        issues = detail.get("issues", [])
        return False, [f"{family_name} issues detected: {', '.join(str(i) for i in issues[:5])}"]

    if _status_bad(detail):
        status = detail.get("status") or detail.get("state")
        return False, [f"{family_name} status indicates non-compliance: {status}"]

    if _status_ok(detail):
        return True, []

    # Check for any domain-relevant evidence
    if any(detail.get(k) is not None for k in domain_keys):
        return True, []

    return False, [f"No {family_name} evidence found — failing closed"]


# ---------------------------------------------------------------------------
# NIST 800-53 family assertions (20 families)
# ---------------------------------------------------------------------------

@_engine.assertion("family_ac_default")
def family_ac_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """AC — Access Control: looks for IAM, MFA, access review, or policy evidence."""
    domain_keys = [
        "mfa_active", "mfa_enabled", "factors", "enrolled_factors",
        "authenticationMethods", "policies", "access_policy", "user",
        "grantControls", "complianceState",
    ]
    return _eval_domain(detail, domain_keys, "access_control")


@_engine.assertion("family_at_default")
def family_at_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """AT — Awareness & Training: looks for training completion evidence."""
    domain_keys = [
        "completion_pct", "completion_rate", "enrollment_status",
        "training_completed", "campaign_name", "course_name",
    ]
    return _eval_domain(detail, domain_keys, "security_training")


@_engine.assertion("family_au_default")
def family_au_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """AU — Audit & Accountability: looks for logging and trail evidence."""
    domain_keys = [
        "trail", "logName", "log_name", "operationName", "audit_log",
        "cloudtrail_enabled", "detectors", "HubArn", "IsMultiRegionTrail",
    ]
    return _eval_domain(detail, domain_keys, "audit_logging")


@_engine.assertion("family_ca_default")
def family_ca_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CA — Security Assessment: looks for assessment/recorder evidence."""
    domain_keys = [
        "recorder", "assessment_id", "scan_id", "assessment_status",
        "last_assessed", "assessment_date",
    ]
    return _eval_domain(detail, domain_keys, "security_assessment")


@_engine.assertion("family_cm_default")
def family_cm_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CM — Configuration Management: looks for config recorder / change management."""
    domain_keys = [
        "recorder", "configuration", "baseline", "change_id",
        "config_recorder", "component_count",
    ]
    return _eval_domain(detail, domain_keys, "configuration_management")


@_engine.assertion("family_cp_default")
def family_cp_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CP — Contingency Planning: looks for backup and recovery evidence."""
    domain_keys = [
        "backup_status", "recovery_point", "rpo_met", "last_backup",
        "job_name", "backup_count", "recovery_plan",
    ]
    return _eval_domain(detail, domain_keys, "contingency_planning")


@_engine.assertion("family_ia_default")
def family_ia_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """IA — Identification & Authentication: looks for auth and identity evidence."""
    domain_keys = [
        "mfa_active", "mfa_enabled", "password_policy", "authentication",
        "identity_provider", "user_id", "credential",
    ]
    return _eval_domain(detail, domain_keys, "identification_authentication")


@_engine.assertion("family_ir_default")
def family_ir_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """IR — Incident Response: looks for SIEM and incident evidence."""
    domain_keys = [
        "incident_id", "alert_id", "detection_rules", "siem_rules",
        "enabled_rules", "playbook", "runbook",
    ]
    return _eval_domain(detail, domain_keys, "incident_response")


@_engine.assertion("family_ma_default")
def family_ma_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """MA — Maintenance: looks for patch/maintenance schedule evidence."""
    domain_keys = [
        "maintenance_date", "patch_status", "last_patch", "maintenance_window",
        "scheduled_maintenance",
    ]
    return _eval_domain(detail, domain_keys, "maintenance")


@_engine.assertion("family_mp_default")
def family_mp_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """MP — Media Protection: looks for encryption and DLP evidence."""
    domain_keys = [
        "encryption", "dlp_policy", "media_sanitization", "data_classification",
        "ServerSideEncryptionConfiguration",
    ]
    return _eval_domain(detail, domain_keys, "media_protection")


@_engine.assertion("family_pe_default")
def family_pe_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """PE — Physical & Environmental Protection: looks for physical access evidence."""
    domain_keys = [
        "physical_access", "badge_event", "facility_id", "visitor_log",
        "physical_control",
    ]
    return _eval_domain(detail, domain_keys, "physical_protection")


@_engine.assertion("family_pl_default")
def family_pl_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """PL — Planning: looks for policy/planning document evidence."""
    domain_keys = [
        "policy_id", "plan_id", "document_id", "last_updated", "reviewed_at",
        "policy_name", "plan_name",
    ]
    return _eval_domain(detail, domain_keys, "security_planning")


@_engine.assertion("family_pm_default")
def family_pm_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """PM — Program Management: looks for program-level governance evidence."""
    domain_keys = [
        "program_id", "governance", "risk_register", "poam_count",
        "security_program",
    ]
    return _eval_domain(detail, domain_keys, "program_management")


@_engine.assertion("family_ps_default")
def family_ps_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """PS — Personnel Security: looks for HR and personnel records."""
    domain_keys = [
        "background_check_status", "employment_agreement", "nda_signed",
        "employee_id", "onboarding_complete", "termination_date",
    ]
    return _eval_domain(detail, domain_keys, "personnel_security")


@_engine.assertion("family_pt_default")
def family_pt_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """PT — PII Processing & Transparency: looks for privacy evidence."""
    domain_keys = [
        "privacy_notice", "consent_recorded", "data_subject_request",
        "pii_inventory", "privacy_assessment",
    ]
    return _eval_domain(detail, domain_keys, "pii_transparency")


@_engine.assertion("family_ra_default")
def family_ra_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """RA — Risk Assessment: looks for vulnerability scan and risk evidence."""
    domain_keys = [
        "risk_score", "last_scan_date", "scan_count", "vulnerability_count",
        "risk_assessment_date",
    ]
    return _eval_domain(detail, domain_keys, "risk_assessment")


@_engine.assertion("family_sa_default")
def family_sa_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SA — System & Services Acquisition: looks for SDLC/code security evidence."""
    domain_keys = [
        "code_scan", "sast_result", "dependency_check", "approval_status",
        "change_id", "severity",
    ]
    return _eval_domain(detail, domain_keys, "system_acquisition")


@_engine.assertion("family_sc_default")
def family_sc_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SC — System & Communications Protection: looks for network/encryption evidence."""
    domain_keys = [
        "IpPermissions", "security_group", "encryption", "tls_enabled",
        "firewall_rule", "network_policy", "vaultUri",
    ]
    return _eval_domain(detail, domain_keys, "system_communications")


@_engine.assertion("family_si_default")
def family_si_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SI — System & Information Integrity: looks for AV, patching, and SIEM evidence."""
    domain_keys = [
        "detectors", "agent_status", "sensor_status", "detection_rules",
        "last_scan_date", "patch_status", "malware_protection",
    ]
    return _eval_domain(detail, domain_keys, "system_integrity")


@_engine.assertion("family_sr_default")
def family_sr_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SR — Supply Chain Risk Management: looks for vendor/supplier evidence."""
    domain_keys = [
        "vendor_id", "supplier_name", "third_party_assessment",
        "contract_id", "supply_chain_risk",
    ]
    return _eval_domain(detail, domain_keys, "supply_chain")


# ---------------------------------------------------------------------------
# ISO 27001 clause-group assertions (Annex A groups A.5–A.8)
# ---------------------------------------------------------------------------

@_engine.assertion("family_iso_a5_default")
def family_iso_a5_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """ISO A.5 — Organisational controls: policy and governance evidence."""
    domain_keys = [
        "policy_id", "policy_name", "governance", "last_updated",
        "risk_register", "threat_intelligence",
    ]
    return _eval_domain(detail, domain_keys, "iso_a5_organisational")


@_engine.assertion("family_iso_a6_default")
def family_iso_a6_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """ISO A.6 — People controls: personnel and HR evidence."""
    domain_keys = [
        "employee_id", "background_check_status", "nda_signed",
        "training_completed", "employment_agreement",
    ]
    return _eval_domain(detail, domain_keys, "iso_a6_people")


@_engine.assertion("family_iso_a7_default")
def family_iso_a7_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """ISO A.7 — Physical controls: physical access and facility evidence."""
    domain_keys = [
        "physical_access", "badge_event", "facility_id",
        "clean_desk", "physical_inventory",
    ]
    return _eval_domain(detail, domain_keys, "iso_a7_physical")


@_engine.assertion("family_iso_a8_default")
def family_iso_a8_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """ISO A.8 — Technological controls: technical security evidence."""
    domain_keys = [
        "mfa_active", "encryption", "IpPermissions", "detectors",
        "patch_status", "vulnerability_count", "dlp_policy",
    ]
    return _eval_domain(detail, domain_keys, "iso_a8_technological")


# ---------------------------------------------------------------------------
# SOC 2 criteria group assertions
# ---------------------------------------------------------------------------

@_engine.assertion("family_soc2_cc1_default")
def family_soc2_cc1_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC1 — Control Environment."""
    domain_keys = ["governance", "org_structure", "employee_id", "policy_id"]
    return _eval_domain(detail, domain_keys, "soc2_cc1_environment")


@_engine.assertion("family_soc2_cc2_default")
def family_soc2_cc2_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC2 — Communication & Information."""
    domain_keys = ["communication_policy", "policy_id", "training_completed", "notification"]
    return _eval_domain(detail, domain_keys, "soc2_cc2_communication")


@_engine.assertion("family_soc2_cc3_default")
def family_soc2_cc3_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC3 — Risk Assessment."""
    domain_keys = ["risk_score", "risk_register", "vulnerability_count", "last_scan_date"]
    return _eval_domain(detail, domain_keys, "soc2_cc3_risk")


@_engine.assertion("family_soc2_cc4_default")
def family_soc2_cc4_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC4 — Monitoring Activities."""
    domain_keys = ["monitoring_enabled", "audit_log", "siem_rules", "review_date"]
    return _eval_domain(detail, domain_keys, "soc2_cc4_monitoring")


@_engine.assertion("family_soc2_cc5_default")
def family_soc2_cc5_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC5 — Control Activities."""
    domain_keys = ["control_id", "policy_id", "procedure_id", "configuration"]
    return _eval_domain(detail, domain_keys, "soc2_cc5_activities")


@_engine.assertion("family_soc2_cc6_default")
def family_soc2_cc6_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC6 — Logical & Physical Access."""
    domain_keys = [
        "mfa_active", "mfa_enabled", "access_policy", "IpPermissions",
        "physical_access",
    ]
    return _eval_domain(detail, domain_keys, "soc2_cc6_access")


@_engine.assertion("family_soc2_cc7_default")
def family_soc2_cc7_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC7 — System Operations."""
    domain_keys = [
        "detectors", "trail", "detection_rules", "incident_id",
        "alert_id", "audit_log",
    ]
    return _eval_domain(detail, domain_keys, "soc2_cc7_operations")


@_engine.assertion("family_soc2_cc8_default")
def family_soc2_cc8_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC8 — Change Management."""
    domain_keys = ["change_id", "approval_status", "change_request", "backout_plan"]
    return _eval_domain(detail, domain_keys, "soc2_cc8_change")


@_engine.assertion("family_soc2_cc9_default")
def family_soc2_cc9_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 CC9 — Risk Mitigation."""
    domain_keys = ["vendor_id", "risk_acceptance", "compensating_control", "residual_risk"]
    return _eval_domain(detail, domain_keys, "soc2_cc9_risk_mitigation")


@_engine.assertion("family_soc2_a1_default")
def family_soc2_a1_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 A1 — Availability."""
    domain_keys = ["backup_status", "last_backup", "uptime", "recovery_plan", "rpo_met"]
    return _eval_domain(detail, domain_keys, "soc2_a1_availability")


@_engine.assertion("family_soc2_c1_default")
def family_soc2_c1_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 C1 — Confidentiality."""
    domain_keys = [
        "encryption", "ServerSideEncryptionConfiguration",
        "data_classification", "dlp_policy",
    ]
    return _eval_domain(detail, domain_keys, "soc2_c1_confidentiality")


@_engine.assertion("family_soc2_p1_default")
def family_soc2_p1_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 P1 — Privacy."""
    domain_keys = ["privacy_notice", "consent_recorded", "pii_inventory", "data_subject_request"]
    return _eval_domain(detail, domain_keys, "soc2_p1_privacy")


@_engine.assertion("family_soc2_pi1_default")
def family_soc2_pi1_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """SOC 2 PI1 — Processing Integrity."""
    domain_keys = ["processing_integrity", "data_validation", "error_rate", "completeness_check"]
    return _eval_domain(detail, domain_keys, "soc2_pi1_integrity")


# ---------------------------------------------------------------------------
# HIPAA section assertions
# ---------------------------------------------------------------------------

@_engine.assertion("family_hipaa_308_default")
def family_hipaa_308_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """HIPAA 164.308 — Administrative Safeguards."""
    domain_keys = [
        "risk_assessment_date", "training_completed", "incident_id",
        "contingency_plan", "business_associate_id",
    ]
    return _eval_domain(detail, domain_keys, "hipaa_administrative")


@_engine.assertion("family_hipaa_310_default")
def family_hipaa_310_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """HIPAA 164.310 — Physical Safeguards."""
    domain_keys = [
        "physical_access", "facility_id", "workstation_policy",
        "media_disposal", "badge_event",
    ]
    return _eval_domain(detail, domain_keys, "hipaa_physical")


@_engine.assertion("family_hipaa_312_default")
def family_hipaa_312_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """HIPAA 164.312 — Technical Safeguards."""
    domain_keys = [
        "mfa_active", "encryption", "audit_log", "automatic_logoff",
        "authentication", "access_control",
    ]
    return _eval_domain(detail, domain_keys, "hipaa_technical")


@_engine.assertion("family_hipaa_314_default")
def family_hipaa_314_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """HIPAA 164.314 — Organizational Requirements."""
    domain_keys = [
        "business_associate_id", "contract_id", "baa_signed",
        "group_health_plan",
    ]
    return _eval_domain(detail, domain_keys, "hipaa_organizational")


@_engine.assertion("family_hipaa_316_default")
def family_hipaa_316_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """HIPAA 164.316 — Policies & Procedures."""
    domain_keys = [
        "policy_id", "last_updated", "procedure_id", "documentation_date",
    ]
    return _eval_domain(detail, domain_keys, "hipaa_policies")


# ---------------------------------------------------------------------------
# CMMC L2 domain assertions (mirrors NIST families)
# ---------------------------------------------------------------------------

@_engine.assertion("family_cmmc_ac_default")
def family_cmmc_ac_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC AC — Access Control."""
    return family_ac_default(detail, raw_data)


@_engine.assertion("family_cmmc_at_default")
def family_cmmc_at_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC AT — Awareness & Training."""
    return family_at_default(detail, raw_data)


@_engine.assertion("family_cmmc_au_default")
def family_cmmc_au_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC AU — Audit & Accountability."""
    return family_au_default(detail, raw_data)


@_engine.assertion("family_cmmc_cm_default")
def family_cmmc_cm_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC CM — Configuration Management."""
    return family_cm_default(detail, raw_data)


@_engine.assertion("family_cmmc_ia_default")
def family_cmmc_ia_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC IA — Identification & Authentication."""
    return family_ia_default(detail, raw_data)


@_engine.assertion("family_cmmc_ir_default")
def family_cmmc_ir_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC IR — Incident Response."""
    return family_ir_default(detail, raw_data)


@_engine.assertion("family_cmmc_ma_default")
def family_cmmc_ma_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC MA — Maintenance."""
    return family_ma_default(detail, raw_data)


@_engine.assertion("family_cmmc_mp_default")
def family_cmmc_mp_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC MP — Media Protection."""
    return family_mp_default(detail, raw_data)


@_engine.assertion("family_cmmc_pe_default")
def family_cmmc_pe_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC PE — Physical Protection."""
    return family_pe_default(detail, raw_data)


@_engine.assertion("family_cmmc_ps_default")
def family_cmmc_ps_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC PS — Personnel Security."""
    return family_ps_default(detail, raw_data)


@_engine.assertion("family_cmmc_ra_default")
def family_cmmc_ra_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC RA — Risk Assessment."""
    return family_ra_default(detail, raw_data)


@_engine.assertion("family_cmmc_sc_default")
def family_cmmc_sc_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC SC — System & Communications Protection."""
    return family_sc_default(detail, raw_data)


@_engine.assertion("family_cmmc_si_default")
def family_cmmc_si_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """CMMC SI — System & Information Integrity."""
    return family_si_default(detail, raw_data)


# ---------------------------------------------------------------------------
# UCF domain assertions (20 domains)
# ---------------------------------------------------------------------------

@_engine.assertion("family_ucf_gov_default")
def family_ucf_gov_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF GOV — Governance."""
    domain_keys = ["policy_id", "governance", "program_id", "last_updated"]
    return _eval_domain(detail, domain_keys, "ucf_governance")


@_engine.assertion("family_ucf_aim_default")
def family_ucf_aim_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF AIM — Asset & Information Management."""
    domain_keys = ["asset_id", "inventory", "classification", "data_owner"]
    return _eval_domain(detail, domain_keys, "ucf_asset_management")


@_engine.assertion("family_ucf_asm_default")
def family_ucf_asm_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF ASM — Attack Surface Management."""
    domain_keys = ["attack_surface", "exposure", "vulnerability_count", "external_asset"]
    return _eval_domain(detail, domain_keys, "ucf_attack_surface")


@_engine.assertion("family_ucf_acc_default")
def family_ucf_acc_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF ACC — Access Control."""
    return family_ac_default(detail, raw_data)


@_engine.assertion("family_ucf_hrs_default")
def family_ucf_hrs_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF HRS — Human Resources Security."""
    return family_ps_default(detail, raw_data)


@_engine.assertion("family_ucf_net_default")
def family_ucf_net_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF NET — Network Security."""
    domain_keys = [
        "IpPermissions", "security_group", "firewall_rule",
        "network_policy", "segmentation",
    ]
    return _eval_domain(detail, domain_keys, "ucf_network")


@_engine.assertion("family_ucf_log_default")
def family_ucf_log_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF LOG — Logging & Monitoring."""
    return family_au_default(detail, raw_data)


@_engine.assertion("family_ucf_dat_default")
def family_ucf_dat_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF DAT — Data Protection."""
    domain_keys = [
        "encryption", "dlp_policy", "data_classification",
        "ServerSideEncryptionConfiguration", "backup_status",
    ]
    return _eval_domain(detail, domain_keys, "ucf_data_protection")


@_engine.assertion("family_ucf_epp_default")
def family_ucf_epp_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF EPP — Endpoint Protection."""
    domain_keys = [
        "agent_status", "sensor_status", "complianceState",
        "last_seen", "isActive",
    ]
    return _eval_domain(detail, domain_keys, "ucf_endpoint_protection")


@_engine.assertion("family_ucf_rsk_default")
def family_ucf_rsk_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF RSK — Risk Management."""
    return family_ra_default(detail, raw_data)


@_engine.assertion("family_ucf_thr_default")
def family_ucf_thr_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF THR — Threat Management."""
    domain_keys = [
        "detectors", "threat_intelligence", "indicators", "alert_id",
        "detection_rules",
    ]
    return _eval_domain(detail, domain_keys, "ucf_threat_management")


@_engine.assertion("family_ucf_vln_default")
def family_ucf_vln_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF VLN — Vulnerability Management."""
    domain_keys = [
        "vulnerability_count", "last_scan_date", "cve_id",
        "severity", "scan_count",
    ]
    return _eval_domain(detail, domain_keys, "ucf_vulnerability_mgmt")


@_engine.assertion("family_ucf_cfg_default")
def family_ucf_cfg_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF CFG — Configuration & Change Management."""
    return family_cm_default(detail, raw_data)


@_engine.assertion("family_ucf_bcp_default")
def family_ucf_bcp_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF BCP — Business Continuity."""
    return family_cp_default(detail, raw_data)


@_engine.assertion("family_ucf_mon_default")
def family_ucf_mon_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF MON — Monitoring."""
    domain_keys = [
        "monitoring_enabled", "detectors", "siem_rules", "enabled_rules",
        "detection_rules",
    ]
    return _eval_domain(detail, domain_keys, "ucf_monitoring")


@_engine.assertion("family_ucf_com_default")
def family_ucf_com_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF COM — Communications Security."""
    domain_keys = [
        "tls_enabled", "encryption", "IpPermissions", "network_policy",
    ]
    return _eval_domain(detail, domain_keys, "ucf_communications")


@_engine.assertion("family_ucf_tpm_default")
def family_ucf_tpm_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF TPM — Third-Party Management."""
    domain_keys = [
        "vendor_id", "supplier_name", "third_party_assessment",
        "contract_id", "baa_signed",
    ]
    return _eval_domain(detail, domain_keys, "ucf_third_party")


@_engine.assertion("family_ucf_dev_default")
def family_ucf_dev_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF DEV — Secure Development."""
    domain_keys = [
        "code_scan", "sast_result", "dependency_check",
        "severity", "change_id",
    ]
    return _eval_domain(detail, domain_keys, "ucf_secure_development")


@_engine.assertion("family_ucf_phy_default")
def family_ucf_phy_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF PHY — Physical Security."""
    return family_pe_default(detail, raw_data)


@_engine.assertion("family_ucf_pri_default")
def family_ucf_pri_default(detail: dict, raw_data: dict) -> tuple[bool, list[str]]:
    """UCF PRI — Privacy."""
    domain_keys = [
        "privacy_notice", "consent_recorded", "pii_inventory",
        "data_subject_request", "gdpr_lawful_basis",
    ]
    return _eval_domain(detail, domain_keys, "ucf_privacy")


# ---------------------------------------------------------------------------
# Family → assertion name mapping tables
# ---------------------------------------------------------------------------

# NIST 800-53 family prefix → assertion name
_NIST_FAMILY_MAP: dict[str, str] = {
    "AC": "family_ac_default",
    "AT": "family_at_default",
    "AU": "family_au_default",
    "CA": "family_ca_default",
    "CM": "family_cm_default",
    "CP": "family_cp_default",
    "IA": "family_ia_default",
    "IR": "family_ir_default",
    "MA": "family_ma_default",
    "MP": "family_mp_default",
    "PE": "family_pe_default",
    "PL": "family_pl_default",
    "PM": "family_pm_default",
    "PS": "family_ps_default",
    "PT": "family_pt_default",
    "RA": "family_ra_default",
    "SA": "family_sa_default",
    "SC": "family_sc_default",
    "SI": "family_si_default",
    "SR": "family_sr_default",
}

# ISO 27001 clause group → assertion name (based on Annex A number prefix)
_ISO27001_FAMILY_MAP: dict[str, str] = {
    "A5": "family_iso_a5_default",
    "A6": "family_iso_a6_default",
    "A7": "family_iso_a7_default",
    "A8": "family_iso_a8_default",
}

# SOC 2 criteria group → assertion name
_SOC2_FAMILY_MAP: dict[str, str] = {
    "CC1": "family_soc2_cc1_default",
    "CC2": "family_soc2_cc2_default",
    "CC3": "family_soc2_cc3_default",
    "CC4": "family_soc2_cc4_default",
    "CC5": "family_soc2_cc5_default",
    "CC6": "family_soc2_cc6_default",
    "CC7": "family_soc2_cc7_default",
    "CC8": "family_soc2_cc8_default",
    "CC9": "family_soc2_cc9_default",
    "A1": "family_soc2_a1_default",
    "C1": "family_soc2_c1_default",
    "P1": "family_soc2_p1_default",
    "PI1": "family_soc2_pi1_default",
}

# HIPAA section → assertion name
_HIPAA_FAMILY_MAP: dict[str, str] = {
    "164.308": "family_hipaa_308_default",
    "164.310": "family_hipaa_310_default",
    "164.312": "family_hipaa_312_default",
    "164.314": "family_hipaa_314_default",
    "164.316": "family_hipaa_316_default",
}

# CMMC L2 domain → assertion name
_CMMC_FAMILY_MAP: dict[str, str] = {
    "AC": "family_cmmc_ac_default",
    "AT": "family_cmmc_at_default",
    "AU": "family_cmmc_au_default",
    "CM": "family_cmmc_cm_default",
    "IA": "family_cmmc_ia_default",
    "IR": "family_cmmc_ir_default",
    "MA": "family_cmmc_ma_default",
    "MP": "family_cmmc_mp_default",
    "PE": "family_cmmc_pe_default",
    "PS": "family_cmmc_ps_default",
    "RA": "family_cmmc_ra_default",
    "SC": "family_cmmc_sc_default",
    "SI": "family_cmmc_si_default",
}

# UCF domain → assertion name (domain extracted from UCF-DOMAIN-N)
_UCF_FAMILY_MAP: dict[str, str] = {
    "GOV": "family_ucf_gov_default",
    "AIM": "family_ucf_aim_default",
    "ASM": "family_ucf_asm_default",
    "ACC": "family_ucf_acc_default",
    "HRS": "family_ucf_hrs_default",
    "NET": "family_ucf_net_default",
    "LOG": "family_ucf_log_default",
    "DAT": "family_ucf_dat_default",
    "EPP": "family_ucf_epp_default",
    "RSK": "family_ucf_rsk_default",
    "THR": "family_ucf_thr_default",
    "VLN": "family_ucf_vln_default",
    "CFG": "family_ucf_cfg_default",
    "BCP": "family_ucf_bcp_default",
    "MON": "family_ucf_mon_default",
    "COM": "family_ucf_com_default",
    "TPM": "family_ucf_tpm_default",
    "DEV": "family_ucf_dev_default",
    "PHY": "family_ucf_phy_default",
    "PRI": "family_ucf_pri_default",
    # IAM is used in crosswalk_ucf_nist.yaml (UCF-IAM-N)
    "IAM": "family_ucf_acc_default",
}

# Regex to extract UCF domain: UCF-DOMAIN-N
_UCF_CTRL_RE = re.compile(r"^UCF-([A-Z]+)-\d+")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_family_assertion(framework: str, control_id: str) -> str | None:
    """Return the family-level default assertion name for a control, or None.

    Args:
        framework: Framework identifier (e.g. "nist_800_53", "soc2").
        control_id: Control identifier (e.g. "AC-2", "CC6.1", "UCF-GOV-1").

    Returns:
        Assertion name string if a family default exists, else None.

    Examples:
        >>> get_family_assertion("nist_800_53", "AC-2")
        'family_ac_default'
        >>> get_family_assertion("soc2", "CC6.3")
        'family_soc2_cc6_default'
        >>> get_family_assertion("ucf", "UCF-GOV-1")
        'family_ucf_gov_default'
        >>> get_family_assertion("hipaa", "164.312(a)(1)")
        'family_hipaa_312_default'
    """
    fw = framework.lower()

    if fw == "nist_800_53":
        # Extract family prefix: AC-2 → AC, SC-7 → SC, AC-2(1) → AC
        m = re.match(r"^([A-Z]+)", control_id)
        if m:
            return _NIST_FAMILY_MAP.get(m.group(1))

    elif fw == "iso_27001":
        # A.5.1 → group A5, A.8.20 → group A8
        m = re.match(r"^(A)\.(\d+)\.", control_id)
        if m:
            group_key = m.group(1) + m.group(2)
            return _ISO27001_FAMILY_MAP.get(group_key)

    elif fw == "soc2":
        # CC6.1 → CC6, A1.1 → A1, PI1.1 → PI1, C1.1 → C1, P1.1 → P1
        m = re.match(r"^(PI1|CC\d|A1|C1|P1)", control_id)
        if m:
            return _SOC2_FAMILY_MAP.get(m.group(1))

    elif fw == "hipaa":
        # 164.308(a)(1) → 164.308
        for section in _HIPAA_FAMILY_MAP:
            if control_id.startswith(section):
                return _HIPAA_FAMILY_MAP[section]

    elif fw == "cmmc_l2":
        # AC.L2-3.1.1 → AC
        m = re.match(r"^([A-Z]+)\.", control_id)
        if m:
            return _CMMC_FAMILY_MAP.get(m.group(1))

    elif fw == "ucf":
        # UCF-GOV-1 → GOV
        m = _UCF_CTRL_RE.match(control_id)
        if m:
            return _UCF_FAMILY_MAP.get(m.group(1))

    return None


def register_family_assertions(engine: "AssertionEngine") -> int:
    """Bind family-level assertions to all controls that lack a specific binding.

    Iterates over every (framework, control_id) pair already known to the engine
    (i.e. loaded from the framework YAMLs via the mapper) and for controls with
    no assertion bound, binds the appropriate family default.

    Because this function relies on controls being pre-loaded into the engine's
    control registry, it should be called AFTER assertions.py has run its
    module-level bindings AND after any crosswalk propagation.

    Args:
        engine: The AssertionEngine singleton.

    Returns:
        Number of new bindings registered.
    """
    bound = 0
    for (fw, ctrl_id) in list(engine._control_assertions.keys()):
        # Already has a binding — skip
        if engine.get_assertion_for_control(fw, ctrl_id):
            continue
        assertion_name = get_family_assertion(fw, ctrl_id)
        if assertion_name:
            engine.bind_control(fw, ctrl_id, assertion_name)
            bound += 1
            log.debug("Family default bound: %s → %s/%s", assertion_name, fw, ctrl_id)

    log.info("register_family_assertions: bound %d family defaults", bound)
    return bound
