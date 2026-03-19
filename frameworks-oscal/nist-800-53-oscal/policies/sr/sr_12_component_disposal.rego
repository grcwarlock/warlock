package nist.sr.sr_12

import rego.v1

# SR-12: Component Disposal

deny_no_disposal_policy contains msg if {
	not input.normalized_data.component_disposal
	msg := "SR-12: No component disposal policy established"
}

deny_no_sanitization_procedures contains msg if {
	cd := input.normalized_data.component_disposal
	not cd.sanitization_procedures
	msg := "SR-12: No data sanitization procedures defined for component disposal"
}

deny_component_not_sanitized contains msg if {
	some component in input.normalized_data.disposed_components
	not component.data_sanitized
	msg := sprintf("SR-12: Disposed component '%s' was not sanitized before disposal", [component.name])
}

deny_no_disposal_records contains msg if {
	cd := input.normalized_data.component_disposal
	not cd.disposal_records_maintained
	msg := "SR-12: No records maintained for component disposal activities"
}

deny_no_disposal_verification contains msg if {
	some component in input.normalized_data.disposed_components
	not component.disposal_verified
	msg := sprintf("SR-12: Disposal of component '%s' has not been verified", [component.name])
}

default compliant := false

compliant if {
	count(deny_no_disposal_policy) == 0
	count(deny_no_sanitization_procedures) == 0
	count(deny_component_not_sanitized) == 0
	count(deny_no_disposal_records) == 0
	count(deny_no_disposal_verification) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_disposal_policy],
		[f | some f in deny_no_sanitization_procedures],
	),
	array.concat(
		[f | some f in deny_component_not_sanitized],
		array.concat(
			[f | some f in deny_no_disposal_records],
			[f | some f in deny_no_disposal_verification],
		),
	),
)

result := {
	"control_id": "SR-12",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
