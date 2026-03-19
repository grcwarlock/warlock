package nist.sa.sa_22

import rego.v1

# SA-22: Unsupported System Components

deny_no_unsupported_tracking contains msg if {
	not input.normalized_data.unsupported_components
	msg := "SA-22: No process for tracking unsupported system components"
}

deny_unsupported_component_in_use contains msg if {
	some component in input.normalized_data.system_components
	component.end_of_life
	not component.replacement_planned
	msg := sprintf("SA-22: Unsupported component '%s' (version %s) is in use with no replacement plan", [component.name, component.version])
}

deny_no_mitigation contains msg if {
	some component in input.normalized_data.system_components
	component.end_of_life
	not component.risk_mitigated
	msg := sprintf("SA-22: Unsupported component '%s' has no risk mitigation in place", [component.name])
}

deny_eol_approaching contains msg if {
	some component in input.normalized_data.system_components
	component.days_to_eol >= 0
	component.days_to_eol < 180
	not component.replacement_planned
	msg := sprintf("SA-22: Component '%s' reaches end of life in %d days with no replacement plan", [component.name, component.days_to_eol])
}

deny_unsupported_inventory_outdated contains msg if {
	uc := input.normalized_data.unsupported_components
	uc.last_review_days > 90
	msg := sprintf("SA-22: Unsupported components inventory has not been reviewed in %d days", [uc.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_unsupported_tracking) == 0
	count(deny_unsupported_component_in_use) == 0
	count(deny_no_mitigation) == 0
	count(deny_eol_approaching) == 0
	count(deny_unsupported_inventory_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_unsupported_tracking],
		[f | some f in deny_unsupported_component_in_use],
	),
	array.concat(
		[f | some f in deny_no_mitigation],
		array.concat(
			[f | some f in deny_eol_approaching],
			[f | some f in deny_unsupported_inventory_outdated],
		),
	),
)

result := {
	"control_id": "SA-22",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
