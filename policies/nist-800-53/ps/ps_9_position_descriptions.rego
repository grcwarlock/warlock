package nist.ps.ps_9

import rego.v1

# PS-9: Position Descriptions

deny_no_position_descriptions contains msg if {
	not input.normalized_data.position_descriptions
	msg := "PS-9: Position descriptions do not incorporate security and privacy roles and responsibilities"
}

deny_position_missing_security_role contains msg if {
	some position in input.normalized_data.positions
	position.has_security_responsibilities
	not position.security_role_in_description
	msg := sprintf("PS-9: Position '%s' does not document security responsibilities in position description", [position.title])
}

deny_descriptions_not_reviewed contains msg if {
	pd := input.normalized_data.position_descriptions
	pd.last_review_days > 365
	msg := sprintf("PS-9: Position descriptions have not been reviewed in %d days", [pd.last_review_days])
}

deny_no_accountability contains msg if {
	some position in input.normalized_data.positions
	position.has_security_responsibilities
	not position.accountability_defined
	msg := sprintf("PS-9: No accountability measures defined for security responsibilities in position '%s'", [position.title])
}

default compliant := false

compliant if {
	count(deny_no_position_descriptions) == 0
	count(deny_position_missing_security_role) == 0
	count(deny_descriptions_not_reviewed) == 0
	count(deny_no_accountability) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_position_descriptions],
		[f | some f in deny_position_missing_security_role],
	),
	array.concat(
		[f | some f in deny_descriptions_not_reviewed],
		[f | some f in deny_no_accountability],
	),
)

result := {
	"control_id": "PS-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "low",
}
