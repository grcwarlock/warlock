package hipaa.s164_316.s164_316_a

import rego.v1

# 164.316(a): Policies and Procedures
# Requires implementation of reasonable and appropriate policies and
# procedures to comply with the Security Rule standards

deny_no_security_policies contains msg if {
	not input.normalized_data.policies.security_policies_documented
	msg := "164.316(a): Security policies are not documented — must implement reasonable and appropriate policies to comply with the HIPAA Security Rule"
}

deny_no_policy_review_cycle contains msg if {
	input.normalized_data.policies.security_policies_documented
	not input.normalized_data.policies.policy_review_scheduled
	msg := "164.316(a): No policy review cycle scheduled — must periodically review and update policies in response to environmental or operational changes"
}

deny_policies_not_reviewed contains msg if {
	input.normalized_data.policies.security_policies_documented
	input.normalized_data.policies.policy_review_scheduled
	input.normalized_data.policies.last_policy_review_days > 365
	msg := sprintf("164.316(a): Security policies have not been reviewed in %d days — must review at least annually", [input.normalized_data.policies.last_policy_review_days])
}

default compliant := false

compliant if {
	count(deny_no_security_policies) == 0
	count(deny_no_policy_review_cycle) == 0
	count(deny_policies_not_reviewed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_security_policies],
		[f | some f in deny_no_policy_review_cycle],
	),
	[f | some f in deny_policies_not_reviewed],
)

result := {
	"control_id": "164.316(a)",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
