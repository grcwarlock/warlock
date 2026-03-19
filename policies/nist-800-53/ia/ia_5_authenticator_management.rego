package nist.ia.ia_5

import rego.v1

# IA-5: Authenticator Management
# Manage information system authenticators by verifying identity
# before distributing authenticators, enforcing complexity, and
# ensuring proper rotation.

deny_weak_password_policy contains msg if {
	input.normalized_data.password_policy
	policy := input.normalized_data.password_policy
	policy.minimum_password_length < 14
	msg := sprintf("IA-5: Password policy minimum length (%d) is below 14 characters", [policy.minimum_password_length])
}

deny_no_complexity contains msg if {
	input.normalized_data.password_policy
	policy := input.normalized_data.password_policy
	not policy.require_uppercase_characters
	msg := "IA-5: Password policy does not require uppercase characters"
}

deny_no_complexity contains msg if {
	input.normalized_data.password_policy
	policy := input.normalized_data.password_policy
	not policy.require_symbols
	msg := "IA-5: Password policy does not require symbols"
}

deny_no_rotation contains msg if {
	some user in input.normalized_data.users
	some key in user.access_keys
	key.status == "Active"
	key.last_used_days > 90
	msg := sprintf("IA-5: User '%s' access key not rotated in %d days", [user.username, key.last_used_days])
}

deny_stale_credentials contains msg if {
	some user in input.normalized_data.users
	user.last_activity != ""
	user.last_activity_days > 180
	msg := sprintf("IA-5: User '%s' has not authenticated in %d days", [user.username, user.last_activity_days])
}

default compliant := false

compliant if {
	count(deny_weak_password_policy) == 0
	count(deny_no_complexity) == 0
	count(deny_no_rotation) == 0
	count(deny_stale_credentials) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_weak_password_policy],
		[f | some f in deny_no_complexity],
	),
	array.concat(
		[f | some f in deny_no_rotation],
		[f | some f in deny_stale_credentials],
	),
)

result := {
	"control_id": "IA-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
