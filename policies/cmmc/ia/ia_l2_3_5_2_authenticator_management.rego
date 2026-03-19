package cmmc.ia.ia_l2_3_5_2

import rego.v1

# IA.L2-3.5.2: Authenticator Management
# Authenticate (or verify) the identities of users, processes, or devices as a prerequisite to allowing access

deny_weak_password_policy contains msg if {
	some policy in input.normalized_data.password_policies
	policy.minimum_length < 14
	msg := sprintf("IA.L2-3.5.2: Password policy '%s' requires only %d characters — minimum 14 required for CUI systems", [policy.name, policy.minimum_length])
}

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	user.enabled
	not user.mfa_enabled
	msg := sprintf("IA.L2-3.5.2: User '%s' does not have multi-factor authentication enabled", [user.username])
}

deny_stale_access_keys contains msg if {
	some user in input.normalized_data.users
	some key in user.access_keys
	key.status == "Active"
	key.age_days > 90
	msg := sprintf("IA.L2-3.5.2: User '%s' has an access key older than 90 days — rotate immediately", [user.username])
}

deny_no_password_expiry contains msg if {
	some policy in input.normalized_data.password_policies
	not policy.expiration_enabled
	msg := sprintf("IA.L2-3.5.2: Password policy '%s' does not enforce password expiration", [policy.name])
}

default compliant := false

compliant if {
	count(deny_weak_password_policy) == 0
	count(deny_no_mfa) == 0
	count(deny_stale_access_keys) == 0
	count(deny_no_password_expiry) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_weak_password_policy],
		[f | some f in deny_no_mfa],
	),
	array.concat(
		[f | some f in deny_stale_access_keys],
		[f | some f in deny_no_password_expiry],
	),
)

result := {
	"control_id": "IA.L2-3.5.2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
