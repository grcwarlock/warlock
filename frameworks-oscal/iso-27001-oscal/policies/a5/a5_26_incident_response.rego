package iso_27001.a5.a5_26

import rego.v1

# A.5.26: Response to Information Security Incidents
# Validates incident response procedures and automation

deny_no_ir_automation contains msg if {
	not input.normalized_data.ssm.ir_automation_documents_exist
	msg := "A.5.26: No automated incident response SSM documents are configured"
}

deny_no_detective contains msg if {
	not input.normalized_data.detective.enabled
	msg := "A.5.26: Amazon Detective is not enabled for incident investigation"
}

deny_no_auto_remediation contains msg if {
	not input.normalized_data.config.auto_remediation_configured
	msg := "A.5.26: No AWS Config auto-remediation rules for common security findings"
}

deny_no_ir_procedure contains msg if {
	not input.normalized_data.policies.incident_response_procedure_documented
	msg := "A.5.26: No documented incident response procedure exists"
}

deny_findings_not_notified contains msg if {
	input.normalized_data.security_hub.enabled
	input.normalized_data.security_hub.notified_findings_count == 0
	input.normalized_data.security_hub.total_findings_count > 0
	msg := "A.5.26: Security Hub findings exist but none have been moved to NOTIFIED status"
}

default compliant := false

compliant if {
	count(deny_no_ir_automation) == 0
	count(deny_no_detective) == 0
	count(deny_no_ir_procedure) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ir_automation],
		[f | some f in deny_no_detective],
	),
	array.concat(
		[f | some f in deny_no_auto_remediation],
		array.concat(
			[f | some f in deny_no_ir_procedure],
			[f | some f in deny_findings_not_notified],
		),
	),
)

result := {
	"control_id": "A.5.26",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
