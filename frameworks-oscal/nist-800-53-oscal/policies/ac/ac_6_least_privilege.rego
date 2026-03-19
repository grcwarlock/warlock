package nist.ac.ac_6

import rego.v1

# AC-6: Least Privilege

deny_wildcard_actions contains msg if {
	some user in input.normalized_data.users
	some policy in user.policies
	policy.effect == "Allow"
	policy.action == "*"
	policy.resource == "*"
	not policy.is_aws_managed
	msg := sprintf("AC-6: User '%s' has wildcard admin policy '%s'", [user.username, policy.name])
}

deny_unused_credentials contains msg if {
	some user in input.normalized_data.users
	some key in user.access_keys
	key.status == "Active"
	key.last_used_days > 90
	msg := sprintf("AC-6: User '%s' has unused access key (last used %d days ago)", [user.username, key.last_used_days])
}

default compliant := false

compliant if {
	count(deny_wildcard_actions) == 0
	count(deny_unused_credentials) == 0
}

findings := array.concat(
	[f | some f in deny_wildcard_actions],
	[f | some f in deny_unused_credentials],
)

result := {
	"control_id": "AC-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
