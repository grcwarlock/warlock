package iso_27001.a5.a5_01

import rego.v1

# A.5.1: Policies for Information Security
# Validates that information security policies are defined, approved, and current

deny_no_security_policy contains msg if {
	not input.normalized_data.policies.information_security_policy
	msg := "A.5.1: No information security policy is defined or published"
}

deny_policy_not_approved contains msg if {
	policy := input.normalized_data.policies.information_security_policy
	not policy.approved
	msg := "A.5.1: Information security policy has not been approved by management"
}

deny_policy_outdated contains msg if {
	policy := input.normalized_data.policies.information_security_policy
	policy.last_review_days > 365
	msg := sprintf("A.5.1: Information security policy has not been reviewed in %d days (max 365)", [policy.last_review_days])
}

deny_no_scp_baseline contains msg if {
	not input.normalized_data.organization.scp_policies_exist
	msg := "A.5.1: No Service Control Policies (SCPs) exist to enforce security baseline"
}

deny_policy_not_communicated contains msg if {
	policy := input.normalized_data.policies.information_security_policy
	not policy.communicated
	msg := "A.5.1: Information security policy has not been communicated to relevant personnel"
}

default compliant := false

compliant if {
	count(deny_no_security_policy) == 0
	count(deny_policy_not_approved) == 0
	count(deny_policy_outdated) == 0
	count(deny_no_scp_baseline) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_policy],
		[f | some f in deny_policy_not_approved],
	),
	array.concat(
		[f | some f in deny_policy_outdated],
		array.concat(
			[f | some f in deny_no_scp_baseline],
			[f | some f in deny_policy_not_communicated],
		),
	),
)

result := {
	"control_id": "A.5.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
