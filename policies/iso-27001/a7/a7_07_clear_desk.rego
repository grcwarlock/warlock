package iso_27001.a7.a7_07

import rego.v1

# A.7.7: Clear Desk and Clear Screen
# Validates screen lock policies and session timeout configurations

deny_no_password_policy contains msg if {
	not input.normalized_data.iam.password_policy
	msg := "A.7.7: No IAM password policy configured for session controls"
}

deny_long_session_duration contains msg if {
	some role in input.normalized_data.iam.roles
	role.max_session_duration > 3600
	msg := sprintf("A.7.7: Role '%s' allows sessions up to %d seconds — maximum 1 hour recommended", [role.name, role.max_session_duration])
}

deny_no_session_duration_scp contains msg if {
	not input.normalized_data.organization.session_duration_scp_exists
	msg := "A.7.7: No SCP enforces maximum session duration for clear screen policy"
}

deny_no_clear_desk_policy contains msg if {
	not input.normalized_data.policies.clear_desk_policy_documented
	msg := "A.7.7: No clear desk and clear screen policy is documented"
}

default compliant := false

compliant if {
	count(deny_no_password_policy) == 0
	count(deny_long_session_duration) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_password_policy],
		[f | some f in deny_long_session_duration],
	),
	array.concat(
		[f | some f in deny_no_session_duration_scp],
		[f | some f in deny_no_clear_desk_policy],
	),
)

result := {
	"control_id": "A.7.7",
	"compliant": compliant,
	"findings": findings,
	"severity": "low",
}
