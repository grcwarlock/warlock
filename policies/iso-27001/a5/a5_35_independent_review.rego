package iso_27001.a5.a5_35

import rego.v1

# A.5.35: Independent Review of Information Security
# Validates independent security reviews are conducted

deny_no_audit_manager contains msg if {
	not input.normalized_data.audit_manager.enabled
	msg := "A.5.35: Audit Manager is not enabled for independent review evidence collection"
}

deny_no_active_assessments contains msg if {
	input.normalized_data.audit_manager.enabled
	count(input.normalized_data.audit_manager.assessments) == 0
	msg := "A.5.35: No active Audit Manager assessments for independent review"
}

deny_no_cis_benchmark contains msg if {
	input.normalized_data.security_hub.enabled
	not input.normalized_data.security_hub.cis_benchmark_enabled
	msg := "A.5.35: CIS Benchmark standard not enabled in Security Hub for independent assessment"
}

deny_no_assessment_reports contains msg if {
	input.normalized_data.audit_manager.enabled
	count(input.normalized_data.audit_manager.assessment_reports) == 0
	msg := "A.5.35: No assessment reports generated from Audit Manager"
}

default compliant := false

compliant if {
	count(deny_no_audit_manager) == 0
	count(deny_no_active_assessments) == 0
	count(deny_no_cis_benchmark) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_audit_manager],
		[f | some f in deny_no_active_assessments],
	),
	array.concat(
		[f | some f in deny_no_cis_benchmark],
		[f | some f in deny_no_assessment_reports],
	),
)

result := {
	"control_id": "A.5.35",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
