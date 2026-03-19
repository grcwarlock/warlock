package nist.sr.sr_1

import rego.v1

# SR-1: Policy and Procedures

deny_no_scrm_policy contains msg if {
	not input.normalized_data.supply_chain_policy
	msg := "SR-1: No supply chain risk management policy established"
}

deny_policy_not_approved contains msg if {
	policy := input.normalized_data.supply_chain_policy
	not policy.approved
	msg := "SR-1: Supply chain risk management policy has not been approved"
}

deny_policy_outdated contains msg if {
	policy := input.normalized_data.supply_chain_policy
	policy.last_review_days > 365
	msg := sprintf("SR-1: Supply chain risk management policy has not been reviewed in %d days", [policy.last_review_days])
}

deny_no_procedures contains msg if {
	policy := input.normalized_data.supply_chain_policy
	not policy.procedures_documented
	msg := "SR-1: Supply chain risk management procedures have not been documented"
}

deny_procedures_outdated contains msg if {
	policy := input.normalized_data.supply_chain_policy
	policy.procedures_last_review_days > 365
	msg := sprintf("SR-1: Supply chain risk management procedures have not been reviewed in %d days", [policy.procedures_last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_scrm_policy) == 0
	count(deny_policy_not_approved) == 0
	count(deny_policy_outdated) == 0
	count(deny_no_procedures) == 0
	count(deny_procedures_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_scrm_policy],
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
	"control_id": "SR-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
