package nist.ps.ps_2

import rego.v1

# PS-2: Position Risk Designation

deny_no_risk_designations contains msg if {
	not input.normalized_data.position_risk_designations
	msg := "PS-2: Position risk designations have not been assigned"
}

deny_position_no_designation contains msg if {
	some position in input.normalized_data.positions
	not position.risk_designation
	msg := sprintf("PS-2: Position '%s' does not have a risk designation assigned", [position.title])
}

deny_designation_no_screening_criteria contains msg if {
	some position in input.normalized_data.positions
	position.risk_designation
	not position.screening_criteria_established
	msg := sprintf("PS-2: Position '%s' has risk designation but no screening criteria established", [position.title])
}

deny_designations_not_reviewed contains msg if {
	prd := input.normalized_data.position_risk_designations
	prd.last_review_days > 365
	msg := sprintf("PS-2: Position risk designations have not been reviewed in %d days", [prd.last_review_days])
}

deny_designation_not_consistent contains msg if {
	some position in input.normalized_data.positions
	position.risk_designation
	not position.consistent_with_opm_policy
	msg := sprintf("PS-2: Position '%s' risk designation is not consistent with OPM policy and guidance", [position.title])
}

default compliant := false

compliant if {
	count(deny_no_risk_designations) == 0
	count(deny_position_no_designation) == 0
	count(deny_designation_no_screening_criteria) == 0
	count(deny_designations_not_reviewed) == 0
	count(deny_designation_not_consistent) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_designations],
		[f | some f in deny_position_no_designation],
	),
	array.concat(
		[f | some f in deny_designation_no_screening_criteria],
		array.concat(
			[f | some f in deny_designations_not_reviewed],
			[f | some f in deny_designation_not_consistent],
		),
	),
)

result := {
	"control_id": "PS-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
