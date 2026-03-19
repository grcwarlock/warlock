package nist.sa.sa_20

import rego.v1

# SA-20: Customized Development of Critical Components

deny_no_custom_dev_policy contains msg if {
	not input.normalized_data.customized_development
	msg := "SA-20: No policy for customized development of critical components"
}

deny_critical_component_not_identified contains msg if {
	cd := input.normalized_data.customized_development
	not cd.critical_components_identified
	msg := "SA-20: Critical components requiring customized development have not been identified"
}

deny_no_reimplementation_plan contains msg if {
	cd := input.normalized_data.customized_development
	not cd.reimplementation_plan
	msg := "SA-20: No reimplementation or custom development plan for critical components"
}

deny_custom_dev_not_reviewed contains msg if {
	cd := input.normalized_data.customized_development
	cd.last_review_days > 365
	msg := sprintf("SA-20: Customized development decisions have not been reviewed in %d days", [cd.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_custom_dev_policy) == 0
	count(deny_critical_component_not_identified) == 0
	count(deny_no_reimplementation_plan) == 0
	count(deny_custom_dev_not_reviewed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_custom_dev_policy],
		[f | some f in deny_critical_component_not_identified],
	),
	array.concat(
		[f | some f in deny_no_reimplementation_plan],
		[f | some f in deny_custom_dev_not_reviewed],
	),
)

result := {
	"control_id": "SA-20",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
