package nist.ac.ac_3

import rego.v1

# AC-3: Access Enforcement
# Enforce approved authorizations for logical access to information
# and system resources in accordance with applicable access control policies.

deny_public_access contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.source == "0.0.0.0/0"
	rule.port_range[0] <= 22
	rule.port_range[1] >= 22
	msg := sprintf("AC-3: Security group '%s' allows public SSH access (0.0.0.0/0:22)", [rule.group_name])
}

deny_public_access contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.source == "0.0.0.0/0"
	rule.port_range[0] <= 3389
	rule.port_range[1] >= 3389
	msg := sprintf("AC-3: Security group '%s' allows public RDP access (0.0.0.0/0:3389)", [rule.group_name])
}

deny_no_default_deny contains msg if {
	not input.normalized_data.default_deny_inbound
	msg := "AC-3: Network does not enforce default-deny inbound"
}

deny_overly_permissive contains msg if {
	some rule in input.normalized_data.rules
	rule.direction == "inbound"
	rule.source == "0.0.0.0/0"
	rule.protocol == "-1"
	msg := sprintf("AC-3: Security group '%s' allows all traffic from any source", [rule.group_name])
}

default compliant := false

compliant if {
	count(deny_public_access) == 0
	count(deny_no_default_deny) == 0
	count(deny_overly_permissive) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_public_access],
		[f | some f in deny_no_default_deny],
	),
	[f | some f in deny_overly_permissive],
)

result := {
	"control_id": "AC-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
