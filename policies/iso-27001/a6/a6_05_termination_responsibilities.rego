package iso_27001.a6.a6_05

import rego.v1

# A.6.5: Responsibilities After Employment Termination or Change
# Validates offboarding procedures revoke access and enforce post-employment obligations

deny_terminated_user_active_keys contains msg if {
	some user in input.normalized_data.users
	user.tags.Status == "Terminated"
	some key in user.access_keys
	key.status == "Active"
	msg := sprintf("A.6.5: Terminated user '%s' still has active access key '%s'", [user.username, key.id])
}

deny_terminated_user_console contains msg if {
	some user in input.normalized_data.users
	user.tags.Status == "Terminated"
	user.console_access
	msg := sprintf("A.6.5: Terminated user '%s' still has console login access", [user.username])
}

deny_terminated_user_in_groups contains msg if {
	some user in input.normalized_data.users
	user.tags.Status == "Terminated"
	count(user.groups) > 0
	msg := sprintf("A.6.5: Terminated user '%s' is still a member of %d IAM groups", [user.username, count(user.groups)])
}

deny_no_offboarding_procedure contains msg if {
	not input.normalized_data.policies.offboarding_procedure_documented
	msg := "A.6.5: No documented offboarding procedure for access revocation"
}

default compliant := false

compliant if {
	count(deny_terminated_user_active_keys) == 0
	count(deny_terminated_user_console) == 0
	count(deny_terminated_user_in_groups) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_terminated_user_active_keys],
		[f | some f in deny_terminated_user_console],
	),
	array.concat(
		[f | some f in deny_terminated_user_in_groups],
		[f | some f in deny_no_offboarding_procedure],
	),
)

result := {
	"control_id": "A.6.5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
