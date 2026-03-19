package nist.ia.ia_2

import rego.v1

# IA-2: Identification and Authentication

deny_no_mfa_privileged contains msg if {
	some user in input.normalized_data.users
	some policy in user.policies
	policy.effect == "Allow"
	policy.action == "*"
	not user.mfa_enabled
	msg := sprintf("IA-2: Privileged user '%s' does not have MFA enabled", [user.username])
}

deny_shared_accounts contains msg if {
	some user in input.normalized_data.users
	contains(lower(user.username), "shared")
	msg := sprintf("IA-2: Possible shared account detected: '%s'", [user.username])
}

deny_generic_accounts contains msg if {
	some user in input.normalized_data.users
	generic_names := {"admin", "test", "temp", "generic", "service"}
	some name in generic_names
	lower(user.username) == name
	msg := sprintf("IA-2: Generic account name detected: '%s'", [user.username])
}

default compliant := false

compliant if {
	count(deny_no_mfa_privileged) == 0
	count(deny_shared_accounts) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa_privileged],
		[f | some f in deny_shared_accounts],
	),
	[f | some f in deny_generic_accounts],
)

result := {
	"control_id": "IA-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
