package nist.pm.pm_7

import rego.v1

# PM-7: Enterprise Architecture

deny_no_enterprise_architecture contains msg if {
	not input.normalized_data.enterprise_architecture
	msg := "PM-7: No enterprise architecture developed that considers information security"
}

deny_no_security_architecture contains msg if {
	ea := input.normalized_data.enterprise_architecture
	not ea.security_architecture_integrated
	msg := "PM-7: Security architecture is not integrated into the enterprise architecture"
}

deny_architecture_outdated contains msg if {
	ea := input.normalized_data.enterprise_architecture
	ea.last_review_days > 365
	msg := sprintf("PM-7: Enterprise architecture has not been reviewed in %d days", [ea.last_review_days])
}

deny_no_reference_models contains msg if {
	ea := input.normalized_data.enterprise_architecture
	not ea.includes_reference_models
	msg := "PM-7: Enterprise architecture does not include security reference models"
}

deny_architecture_not_aligned contains msg if {
	ea := input.normalized_data.enterprise_architecture
	not ea.aligned_with_mission
	msg := "PM-7: Enterprise architecture is not aligned with organizational mission and business processes"
}

default compliant := false

compliant if {
	count(deny_no_enterprise_architecture) == 0
	count(deny_no_security_architecture) == 0
	count(deny_architecture_outdated) == 0
	count(deny_no_reference_models) == 0
	count(deny_architecture_not_aligned) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_enterprise_architecture],
		[f | some f in deny_no_security_architecture],
	),
	array.concat(
		[f | some f in deny_architecture_outdated],
		array.concat(
			[f | some f in deny_no_reference_models],
			[f | some f in deny_architecture_not_aligned],
		),
	),
)

result := {
	"control_id": "PM-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
