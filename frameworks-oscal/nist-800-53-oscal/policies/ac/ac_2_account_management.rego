package nist.ac.ac_2

import rego.v1

# AC-2: Account Management
# Validates identity lifecycle: provisioning, MFA, access key hygiene

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	not user.mfa_enabled
	user.username != "root"
	msg := sprintf("AC-2: User '%s' does not have MFA enabled", [user.username])
}

deny_root_access_keys contains msg if {
	input.normalized_data.root_account.access_keys_present
	msg := "AC-2: Root account has active access keys — remove immediately"
}

deny_inactive_accounts contains msg if {
	some user in input.normalized_data.users
	user.last_activity != ""
	some key in user.access_keys
	key.status == "Active"
	key.last_used_days > 90
	msg := sprintf("AC-2: User '%s' has inactive access key (unused %d days)", [user.username, key.last_used_days])
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_root_access_keys) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa],
		[f | some f in deny_root_access_keys],
	),
	[f | some f in deny_inactive_accounts],
)

result := {
	"control_id": "AC-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
	"checked_users": count(input.normalized_data.users),
}
