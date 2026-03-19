package iso_27001.a8.a8_18

import rego.v1

# A.8.18: Use of Privileged Utility Programs
# Validates privileged utility program usage is restricted and monitored

deny_no_session_logging contains msg if {
	not input.normalized_data.ssm.session_logging_enabled
	msg := "A.8.18: SSM session logging is not enabled — privileged utility usage unaudited"
}

deny_unrestricted_ssm_access contains msg if {
	some role in input.normalized_data.iam.roles
	role_allows_action(role, "ssm:SendCommand")
	not role.is_admin
	not role.has_condition_on_ssm
	msg := sprintf("A.8.18: Role '%s' has unrestricted ssm:SendCommand access", [role.name])
}

deny_no_privileged_action_monitoring contains msg if {
	not input.normalized_data.eventbridge.privileged_action_rule_exists
	msg := "A.8.18: No EventBridge rule monitors privileged utility usage (SendCommand, StartSession)"
}

deny_no_privileged_utility_policy contains msg if {
	not input.normalized_data.iam.deny_privileged_utilities_policy_exists
	msg := "A.8.18: No IAM policy restricts access to privileged utility programs"
}

role_allows_action(role, action) if {
	some a in role.allowed_actions
	a == action
}

default compliant := false

compliant if {
	count(deny_no_session_logging) == 0
	count(deny_unrestricted_ssm_access) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_session_logging],
		[f | some f in deny_unrestricted_ssm_access],
	),
	array.concat(
		[f | some f in deny_no_privileged_action_monitoring],
		[f | some f in deny_no_privileged_utility_policy],
	),
)

result := {
	"control_id": "A.8.18",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
