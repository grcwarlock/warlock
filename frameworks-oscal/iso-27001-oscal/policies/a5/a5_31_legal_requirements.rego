package iso_27001.a5.a5_31

import rego.v1

# A.5.31: Legal, Statutory, Regulatory and Contractual Requirements
# Validates compliance requirements are documented and tracked

deny_no_compliance_standards contains msg if {
	input.normalized_data.security_hub.enabled
	count(input.normalized_data.security_hub.enabled_standards) == 0
	msg := "A.5.31: No compliance standards enabled in Security Hub"
}

deny_no_audit_manager contains msg if {
	not input.normalized_data.audit_manager.enabled
	msg := "A.5.31: AWS Audit Manager is not enabled for compliance tracking"
}

deny_no_active_assessments contains msg if {
	input.normalized_data.audit_manager.enabled
	count(input.normalized_data.audit_manager.assessments) == 0
	msg := "A.5.31: No active Audit Manager assessments for regulatory compliance"
}

deny_no_legal_requirements_documented contains msg if {
	not input.normalized_data.policies.legal_requirements_documented
	msg := "A.5.31: Legal and regulatory requirements are not documented"
}

default compliant := false

compliant if {
	count(deny_no_compliance_standards) == 0
	count(deny_no_audit_manager) == 0
	count(deny_no_active_assessments) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_compliance_standards],
		[f | some f in deny_no_audit_manager],
	),
	array.concat(
		[f | some f in deny_no_active_assessments],
		[f | some f in deny_no_legal_requirements_documented],
	),
)

result := {
	"control_id": "A.5.31",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
