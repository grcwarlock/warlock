package pci_dss.r12

import rego.v1

# PCI DSS 4.0 Requirement 12: Support Information Security with Organizational Policies

deny_policy_outdated contains msg if {
	some policy in input.normalized_data.policies
	policy.days_since_review > 365
	msg := sprintf("R12.1: Security policy '%s' has not been reviewed in %d days", [policy.name, policy.days_since_review])
}

deny_training_incomplete contains msg if {
	input.normalized_data.training.completion_rate < 95
	msg := sprintf("R12.6: Security awareness training completion at %d%% (requires 95%%+)", [input.normalized_data.training.completion_rate])
}

deny_no_ir_plan contains msg if {
	not input.normalized_data.incident_response.plan_tested
	msg := "R12.10: Incident response plan has not been tested within the past year"
}

default compliant := false

compliant if {
	count(deny_policy_outdated) == 0
	count(deny_training_incomplete) == 0
	count(deny_no_ir_plan) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_policy_outdated],
		[f | some f in deny_training_incomplete],
	),
	[f | some f in deny_no_ir_plan],
)

result := {
	"control_id": "R12",
	"framework": "PCI DSS 4.0",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
