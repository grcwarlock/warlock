package nist.cp.cp_1

import rego.v1

# CP-1: Policy and Procedures
# Validates contingency planning policy exists and is current

deny_no_cp_policy contains msg if {
	not input.normalized_data.contingency_policy
	msg := "CP-1: No contingency planning policy document found"
}

deny_no_cp_policy contains msg if {
	input.normalized_data.contingency_policy
	not input.normalized_data.contingency_policy.exists
	msg := "CP-1: Contingency planning policy document does not exist"
}

deny_policy_not_reviewed contains msg if {
	input.normalized_data.contingency_policy.exists
	input.normalized_data.contingency_policy.last_review_days > 365
	msg := sprintf("CP-1: Contingency planning policy has not been reviewed in %d days (exceeds 365-day maximum)", [input.normalized_data.contingency_policy.last_review_days])
}

deny_no_designated_official contains msg if {
	input.normalized_data.contingency_policy.exists
	not input.normalized_data.contingency_policy.designated_official
	msg := "CP-1: No designated official assigned for contingency planning policy oversight"
}

deny_no_scope_defined contains msg if {
	input.normalized_data.contingency_policy.exists
	not input.normalized_data.contingency_policy.scope_defined
	msg := "CP-1: Contingency planning policy does not define scope of applicability"
}

deny_no_dissemination contains msg if {
	input.normalized_data.contingency_policy.exists
	not input.normalized_data.contingency_policy.disseminated
	msg := "CP-1: Contingency planning policy has not been disseminated to relevant personnel"
}

default compliant := false

compliant if {
	count(deny_no_cp_policy) == 0
	count(deny_policy_not_reviewed) == 0
	count(deny_no_designated_official) == 0
	count(deny_no_scope_defined) == 0
	count(deny_no_dissemination) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_cp_policy],
		[f | some f in deny_policy_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_designated_official],
		array.concat(
			[f | some f in deny_no_scope_defined],
			[f | some f in deny_no_dissemination],
		),
	),
)

result := {
	"control_id": "CP-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
