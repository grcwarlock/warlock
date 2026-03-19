package iso_27001.a5.a5_11

import rego.v1

# A.5.11: Return of Assets
# Validates offboarding process includes asset return and access revocation

deny_orphaned_accounts contains msg if {
	some user in input.normalized_data.users
	user.status == "terminated"
	user.account_enabled
	msg := sprintf("A.5.11: Terminated user '%s' still has an active account", [user.username])
}

deny_terminated_user_access_keys contains msg if {
	some user in input.normalized_data.users
	user.status == "terminated"
	some key in user.access_keys
	key.status == "Active"
	msg := sprintf("A.5.11: Terminated user '%s' still has active access key '%s'", [user.username, key.id])
}

deny_terminated_user_mfa contains msg if {
	some user in input.normalized_data.users
	user.status == "terminated"
	user.mfa_enabled
	msg := sprintf("A.5.11: Terminated user '%s' still has MFA device associated — should be removed", [user.username])
}

deny_terminated_user_console contains msg if {
	some user in input.normalized_data.users
	user.status == "terminated"
	user.console_access
	msg := sprintf("A.5.11: Terminated user '%s' still has console login access", [user.username])
}

deny_no_offboarding_process contains msg if {
	not input.normalized_data.policies.offboarding_process_documented
	msg := "A.5.11: No documented offboarding process for access revocation and asset return"
}

default compliant := false

compliant if {
	count(deny_orphaned_accounts) == 0
	count(deny_terminated_user_access_keys) == 0
	count(deny_terminated_user_console) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_orphaned_accounts],
		[f | some f in deny_terminated_user_access_keys],
	),
	array.concat(
		[f | some f in deny_terminated_user_mfa],
		array.concat(
			[f | some f in deny_terminated_user_console],
			[f | some f in deny_no_offboarding_process],
		),
	),
)

result := {
	"control_id": "A.5.11",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
