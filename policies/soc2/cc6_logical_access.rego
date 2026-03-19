package soc2.cc6

import rego.v1

# SOC 2 CC6.1: Logical and Physical Access Controls
# Maps to NIST AC-2, AC-6

deny_no_mfa contains msg if {
	some user in input.normalized_data.users
	not user.mfa_enabled
	user.username != "root"
	msg := sprintf("CC6.1: User '%s' lacks MFA — logical access control gap", [user.username])
}

deny_excessive_access contains msg if {
	some user in input.normalized_data.users
	some policy in user.policies
	policy.effect == "Allow"
	policy.action == "*"
	policy.resource == "*"
	msg := sprintf("CC6.1: User '%s' has unrestricted access via '%s'", [user.username, policy.name])
}

deny_root_keys contains msg if {
	input.normalized_data.root_account.access_keys_present
	msg := "CC6.1: Root/owner account has programmatic access keys"
}

default compliant := false

compliant if {
	count(deny_no_mfa) == 0
	count(deny_excessive_access) == 0
	count(deny_root_keys) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mfa],
		[f | some f in deny_excessive_access],
	),
	[f | some f in deny_root_keys],
)

result := {
	"control_id": "CC6.1",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
