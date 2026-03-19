package hipaa.s164_312.s164_312_d

import rego.v1

# 164.312(d): Person or Entity Authentication
# Requires procedures to verify that a person or entity seeking access
# to ePHI is who they claim to be

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	user.ephi_access
	not user.mfa_enabled
	msg := sprintf("164.312(d): User '%s' with ePHI access does not have multi-factor authentication enabled", [user.username])
}

deny_weak_password_policy contains msg if {
	input.normalized_data.config.password_policy.min_length < 12
	msg := sprintf("164.312(d): Password minimum length is %d characters — must enforce strong authentication (minimum 12 characters recommended)", [input.normalized_data.config.password_policy.min_length])
}

deny_no_password_expiration contains msg if {
	not input.normalized_data.config.password_policy.expiration_enabled
	msg := "164.312(d): Password expiration is not enforced — must implement procedures to periodically rotate credentials"
}

deny_shared_accounts contains msg if {
	some user in input.normalized_data.users
	user.shared_account
	user.ephi_access
	msg := sprintf("164.312(d): Shared account '%s' has ePHI access — authentication must verify individual identity", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_weak_password_policy) == 0
	count(deny_no_password_expiration) == 0
	count(deny_shared_accounts) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa],
		[f | some f in deny_weak_password_policy],
	),
	array.concat(
		[f | some f in deny_no_password_expiration],
		[f | some f in deny_shared_accounts],
	),
)

result := {
	"control_id": "164.312(d)",
	"compliant": compliant,
	"findings": findings,
	"severity": "critical",
}
