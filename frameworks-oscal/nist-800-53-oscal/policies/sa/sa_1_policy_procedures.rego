package nist.sa.sa_1

import rego.v1

# SA-1: Policy and Procedures

deny_no_acquisition_policy contains msg if {
	not input.normalized_data.acquisition_policy
	msg := "SA-1: No system and services acquisition policy established"
}

deny_policy_not_approved contains msg if {
	policy := input.normalized_data.acquisition_policy
	not policy.approved
	msg := "SA-1: Acquisition policy has not been approved by designated official"
}

deny_policy_outdated contains msg if {
	policy := input.normalized_data.acquisition_policy
	policy.last_review_days > 365
	msg := sprintf("SA-1: Acquisition policy has not been reviewed in %d days", [policy.last_review_days])
}

deny_no_procedures contains msg if {
	policy := input.normalized_data.acquisition_policy
	not policy.procedures_documented
	msg := "SA-1: Acquisition procedures have not been documented"
}

deny_procedures_outdated contains msg if {
	policy := input.normalized_data.acquisition_policy
	policy.procedures_last_review_days > 365
	msg := sprintf("SA-1: Acquisition procedures have not been reviewed in %d days", [policy.procedures_last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_acquisition_policy) == 0
	count(deny_policy_not_approved) == 0
	count(deny_policy_outdated) == 0
	count(deny_no_procedures) == 0
	count(deny_procedures_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_acquisition_policy],
		[f | some f in deny_policy_not_approved],
	),
	array.concat(
		[f | some f in deny_policy_outdated],
		array.concat(
			[f | some f in deny_no_procedures],
			[f | some f in deny_procedures_outdated],
		),
	),
)

result := {
	"control_id": "SA-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
