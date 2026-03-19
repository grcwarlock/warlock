package ucf.aim.ucf_aim_1

import rego.v1

# UCF-AIM-1: AI Policy
# Validates that AI governance policies are defined

deny_no_ai_policy contains msg if {
	not input.normalized_data.policies.ai_governance_policy
	msg := "UCF-AIM-1: No AI governance policy is defined"
}

deny_ai_policy_not_approved contains msg if {
	policy := input.normalized_data.policies.ai_governance_policy
	not policy.approved
	msg := "UCF-AIM-1: AI governance policy has not been approved"
}

default compliant := false

compliant if {
	count(deny_no_ai_policy) == 0
	count(deny_ai_policy_not_approved) == 0
}

findings := array.concat(
	[f | some f in deny_no_ai_policy],
	[f | some f in deny_ai_policy_not_approved],
)

result := {
	"control_id": "UCF-AIM-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
