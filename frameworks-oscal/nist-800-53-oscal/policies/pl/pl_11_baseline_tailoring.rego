package nist.pl.pl_11

import rego.v1

# PL-11: Baseline Tailoring

deny_no_tailoring contains msg if {
	some system in input.normalized_data.planning.systems
	system.control_baseline_selected
	not system.baseline_tailored
	msg := sprintf("PL-11: System '%s' has selected a baseline but has not tailored it to organizational needs", [system.system_id])
}

deny_tailoring_not_documented contains msg if {
	some system in input.normalized_data.planning.systems
	system.baseline_tailored
	not system.tailoring_documented
	msg := sprintf("PL-11: Baseline tailoring for system '%s' is not documented", [system.system_id])
}

deny_tailoring_not_justified contains msg if {
	some system in input.normalized_data.planning.systems
	system.baseline_tailored
	not system.tailoring_justified
	msg := sprintf("PL-11: Baseline tailoring decisions for system '%s' are not justified with rationale", [system.system_id])
}

deny_tailoring_not_approved contains msg if {
	some system in input.normalized_data.planning.systems
	system.baseline_tailored
	not system.tailoring_approved_by_authorizing_official
	msg := sprintf("PL-11: Tailored baseline for system '%s' has not been approved by the authorizing official", [system.system_id])
}

deny_compensating_controls_not_documented contains msg if {
	some system in input.normalized_data.planning.systems
	system.baseline_tailored
	system.has_compensating_controls
	not system.compensating_controls_documented
	msg := sprintf("PL-11: Compensating controls for system '%s' are not documented", [system.system_id])
}

default compliant := false

compliant if {
	count(deny_no_tailoring) == 0
	count(deny_tailoring_not_documented) == 0
	count(deny_tailoring_not_justified) == 0
	count(deny_tailoring_not_approved) == 0
	count(deny_compensating_controls_not_documented) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_tailoring],
		[f | some f in deny_tailoring_not_documented],
	),
	array.concat(
		array.concat(
			[f | some f in deny_tailoring_not_justified],
			[f | some f in deny_tailoring_not_approved],
		),
		[f | some f in deny_compensating_controls_not_documented],
	),
)

result := {
	"control_id": "PL-11",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
