package soc2.cc5

import rego.v1

# SOC 2 CC5: Control Activities (COSO Principles 10-12)
# Control selection, technology controls, policy deployment

deny_no_control_inventory contains msg if {
	not input.normalized_data.governance.control_inventory_exists
	msg := "CC5.1: No control inventory — controls to mitigate risks not identified and documented"
}

deny_low_automation_coverage contains msg if {
	input.normalized_data.governance.control_inventory_exists
	input.normalized_data.governance.automated_control_percentage < 50
	msg := sprintf("CC5.1: Only %d%% of controls are automated — insufficient technology-based control coverage", [input.normalized_data.governance.automated_control_percentage])
}

deny_no_technology_controls contains msg if {
	not input.normalized_data.governance.technology_general_controls_defined
	msg := "CC5.2: Technology general controls (ITGCs) not defined — access, change, and operations controls for IT systems not established"
}

deny_no_segregation_of_duties contains msg if {
	not input.normalized_data.governance.segregation_of_duties_enforced
	msg := "CC5.2: Segregation of duties not enforced — incompatible functions not separated"
}

deny_no_policy_deployment contains msg if {
	not input.normalized_data.governance.policies_distributed
	msg := "CC5.3: Security policies not distributed to personnel — control activities through policies not deployed"
}

deny_stale_policies contains msg if {
	some policy in input.normalized_data.governance.policies
	policy.review_age_days > 365
	msg := sprintf("CC5.3: Policy '%s' not reviewed in %d days — policies must be reviewed at least annually", [policy.name, policy.review_age_days])
}

default compliant := false

compliant if {
	count(deny_no_control_inventory) == 0
	count(deny_low_automation_coverage) == 0
	count(deny_no_technology_controls) == 0
	count(deny_no_segregation_of_duties) == 0
	count(deny_no_policy_deployment) == 0
	count(deny_stale_policies) == 0
}

findings := array.concat(
	array.concat(
		array.concat(
			[f | some f in deny_no_control_inventory],
			[f | some f in deny_low_automation_coverage],
		),
		array.concat(
			[f | some f in deny_no_technology_controls],
			[f | some f in deny_no_segregation_of_duties],
		),
	),
	array.concat(
		[f | some f in deny_no_policy_deployment],
		[f | some f in deny_stale_policies],
	),
)

result := {
	"control_id": "CC5",
	"framework": "SOC 2",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
