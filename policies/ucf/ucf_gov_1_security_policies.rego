package ucf.gov.ucf_gov_1

import rego.v1

# UCF-GOV-1: Security Policies
# Validates that information security policies are defined and current

deny_no_security_policy contains msg if {
	not input.normalized_data.policies.information_security_policy
	msg := "UCF-GOV-1: No information security policy is defined"
}

deny_policy_outdated contains msg if {
	policy := input.normalized_data.policies.information_security_policy
	policy.last_review_days > 365
	msg := sprintf("UCF-GOV-1: Information security policy not reviewed in %d days", [policy.last_review_days])
}

deny_policy_not_approved contains msg if {
	policy := input.normalized_data.policies.information_security_policy
	not policy.approved
	msg := "UCF-GOV-1: Information security policy not approved by management"
}

default compliant := false

compliant if {
	count(deny_no_security_policy) == 0
	count(deny_policy_not_approved) == 0
	count(deny_policy_outdated) == 0
}

findings := array.concat(
	[f | some f in deny_no_security_policy],
	array.concat(
		[f | some f in deny_policy_outdated],
		[f | some f in deny_policy_not_approved],
	),
)

result := {
	"control_id": "UCF-GOV-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
