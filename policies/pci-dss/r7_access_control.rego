package pci_dss.r7

import rego.v1

# PCI DSS 4.0 Requirement 7: Restrict Access by Business Need to Know

deny_excessive_access contains msg if {
	some user in input.normalized_data.users
	some policy in user.policies
	policy.effect == "Allow"
	policy.action == "*"
	policy.resource == "*"
	msg := sprintf("R7.1: User '%s' has unrestricted access via policy '%s'", [user.username, policy.name])
}

deny_no_access_review contains msg if {
	input.normalized_data.access_review.overdue
	msg := sprintf("R7.1: Access review campaign '%s' is overdue", [input.normalized_data.access_review.name])
}

default compliant := false

compliant if {
	count(deny_excessive_access) == 0
	count(deny_no_access_review) == 0
}

findings := array.concat(
	[f | some f in deny_excessive_access],
	[f | some f in deny_no_access_review],
)

result := {
	"control_id": "R7",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
