package nist.pl.pl_10

import rego.v1

# PL-10: Baseline Selection

valid_baselines := {"low", "moderate", "high"}

deny_no_baseline_selected contains msg if {
	some system in input.normalized_data.planning.systems
	not system.control_baseline_selected
	msg := sprintf("PL-10: System '%s' has not selected a security control baseline", [system.system_id])
}

deny_invalid_baseline contains msg if {
	some system in input.normalized_data.planning.systems
	system.control_baseline_selected
	not system.baseline_level in valid_baselines
	msg := sprintf("PL-10: System '%s' has an invalid baseline level '%s'; must be one of: low, moderate, high", [system.system_id, system.baseline_level])
}

deny_baseline_not_justified contains msg if {
	some system in input.normalized_data.planning.systems
	system.control_baseline_selected
	not system.baseline_selection_justified
	msg := sprintf("PL-10: Baseline selection for system '%s' is not justified based on risk assessment", [system.system_id])
}

deny_no_risk_categorization contains msg if {
	some system in input.normalized_data.planning.systems
	not system.fips_199_categorization_completed
	msg := sprintf("PL-10: System '%s' has not completed FIPS 199 security categorization", [system.system_id])
}

default compliant := false

compliant if {
	count(deny_no_baseline_selected) == 0
	count(deny_invalid_baseline) == 0
	count(deny_baseline_not_justified) == 0
	count(deny_no_risk_categorization) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_baseline_selected],
		[f | some f in deny_invalid_baseline],
	),
	array.concat(
		[f | some f in deny_baseline_not_justified],
		[f | some f in deny_no_risk_categorization],
	),
)

result := {
	"control_id": "PL-10",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
