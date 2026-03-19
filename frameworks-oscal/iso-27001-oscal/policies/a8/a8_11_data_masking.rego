package iso_27001.a8.a8_11

import rego.v1

# A.8.11: Data Masking
# Validates data masking is implemented for sensitive data

deny_no_macie contains msg if {
	not input.normalized_data.macie.enabled
	msg := "A.8.11: Macie is not enabled for sensitive data discovery and masking needs assessment"
}

deny_no_classification_jobs contains msg if {
	input.normalized_data.macie.enabled
	count(input.normalized_data.macie.classification_jobs) == 0
	msg := "A.8.11: No Macie classification jobs to identify data requiring masking"
}

deny_high_sensitivity_findings contains msg if {
	input.normalized_data.macie.enabled
	input.normalized_data.macie.high_severity_finding_count > 0
	msg := sprintf("A.8.11: %d high-severity Macie findings — sensitive data may need masking", [input.normalized_data.macie.high_severity_finding_count])
}

deny_no_log_data_protection contains msg if {
	not input.normalized_data.cloudwatch.data_protection_policies_configured
	msg := "A.8.11: No CloudWatch Logs data protection policies for log masking"
}

default compliant := false

compliant if {
	count(deny_no_macie) == 0
	count(deny_no_classification_jobs) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_macie],
		[f | some f in deny_no_classification_jobs],
	),
	array.concat(
		[f | some f in deny_high_sensitivity_findings],
		[f | some f in deny_no_log_data_protection],
	),
)

result := {
	"control_id": "A.8.11",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
