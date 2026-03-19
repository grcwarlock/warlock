package nist.ra.ra_7

import rego.v1

# RA-7: Risk Response

deny_no_risk_response contains msg if {
	not input.normalized_data.risk_response
	msg := "RA-7: No risk response strategy defined"
}

deny_no_response_options contains msg if {
	rr := input.normalized_data.risk_response
	not rr.response_options_defined
	msg := "RA-7: Risk response options (accept, avoid, mitigate, share, transfer) not defined"
}

deny_risks_without_response contains msg if {
	some risk in input.normalized_data.identified_risks
	not risk.response_selected
	msg := sprintf("RA-7: Risk '%s' does not have a response strategy selected", [risk.id])
}

deny_accepted_risk_not_authorized contains msg if {
	some risk in input.normalized_data.identified_risks
	risk.response_selected == "accept"
	not risk.acceptance_authorized
	msg := sprintf("RA-7: Accepted risk '%s' has not been formally authorized by appropriate official", [risk.id])
}

deny_response_not_implemented contains msg if {
	some risk in input.normalized_data.identified_risks
	risk.response_selected == "mitigate"
	not risk.mitigation_implemented
	msg := sprintf("RA-7: Risk '%s' mitigation strategy has not been implemented", [risk.id])
}

default compliant := false

compliant if {
	count(deny_no_risk_response) == 0
	count(deny_no_response_options) == 0
	count(deny_risks_without_response) == 0
	count(deny_accepted_risk_not_authorized) == 0
	count(deny_response_not_implemented) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_risk_response],
		[f | some f in deny_no_response_options],
	),
	array.concat(
		[f | some f in deny_risks_without_response],
		array.concat(
			[f | some f in deny_accepted_risk_not_authorized],
			[f | some f in deny_response_not_implemented],
		),
	),
)

result := {
	"control_id": "RA-7",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
