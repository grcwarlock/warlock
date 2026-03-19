package nist.at.at_1

import rego.v1

# AT-1: Policy and Procedures
# Validates that security awareness and training policy exists and is current

deny_no_training_policy contains msg if {
	not input.normalized_data.training_policy
	msg := "AT-1: No security awareness and training policy document found"
}

deny_no_training_policy contains msg if {
	input.normalized_data.training_policy
	not input.normalized_data.training_policy.exists
	msg := "AT-1: Security awareness and training policy document does not exist"
}

deny_policy_not_reviewed contains msg if {
	input.normalized_data.training_policy.exists
	input.normalized_data.training_policy.last_review_days > 365
	msg := sprintf("AT-1: Training policy has not been reviewed in %d days (exceeds 365-day maximum)", [input.normalized_data.training_policy.last_review_days])
}

deny_no_designated_official contains msg if {
	input.normalized_data.training_policy.exists
	not input.normalized_data.training_policy.designated_official
	msg := "AT-1: No designated official assigned for training policy oversight"
}

deny_no_scope_defined contains msg if {
	input.normalized_data.training_policy.exists
	not input.normalized_data.training_policy.scope_defined
	msg := "AT-1: Training policy does not define scope of applicability"
}

deny_no_dissemination contains msg if {
	input.normalized_data.training_policy.exists
	not input.normalized_data.training_policy.disseminated
	msg := "AT-1: Training policy has not been disseminated to relevant personnel"
}

default compliant := false

compliant if {
	count(deny_no_training_policy) == 0
	count(deny_policy_not_reviewed) == 0
	count(deny_no_designated_official) == 0
	count(deny_no_scope_defined) == 0
	count(deny_no_dissemination) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_training_policy],
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
	"control_id": "AT-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
