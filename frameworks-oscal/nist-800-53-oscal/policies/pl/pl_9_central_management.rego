package nist.pl.pl_9

import rego.v1

# PL-9: Central Management

deny_no_centralized_management contains msg if {
	not input.normalized_data.planning.centralized_management_established
	msg := "PL-9: Organization has not established centralized management for security controls"
}

deny_controls_not_centralized contains msg if {
	some control in input.normalized_data.planning.security_controls
	control.requires_central_management
	not control.centrally_managed
	msg := sprintf("PL-9: Security control '%s' requires central management but is managed locally", [control.control_id])
}

deny_no_central_policy_repository contains msg if {
	not input.normalized_data.planning.central_policy_repository
	msg := "PL-9: Organization does not maintain a central repository for security policies"
}

deny_no_central_monitoring contains msg if {
	not input.normalized_data.planning.centralized_monitoring
	msg := "PL-9: Organization does not have centralized security monitoring capabilities"
}

default compliant := false

compliant if {
	count(deny_no_centralized_management) == 0
	count(deny_controls_not_centralized) == 0
	count(deny_no_central_policy_repository) == 0
	count(deny_no_central_monitoring) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_centralized_management],
		[f | some f in deny_controls_not_centralized],
	),
	array.concat(
		[f | some f in deny_no_central_policy_repository],
		[f | some f in deny_no_central_monitoring],
	),
)

result := {
	"control_id": "PL-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
