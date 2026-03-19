package nist.cp.cp_2

import rego.v1

# CP-2: Contingency Plan
# Validates contingency plan exists, addresses essential missions, and is tested

deny_no_contingency_plan contains msg if {
	not input.normalized_data.contingency_plan
	msg := "CP-2: No contingency plan exists for the system"
}

deny_plan_not_reviewed contains msg if {
	input.normalized_data.contingency_plan
	input.normalized_data.contingency_plan.last_review_days > 365
	msg := sprintf("CP-2: Contingency plan has not been reviewed in %d days (exceeds annual requirement)", [input.normalized_data.contingency_plan.last_review_days])
}

deny_no_essential_missions contains msg if {
	input.normalized_data.contingency_plan
	not input.normalized_data.contingency_plan.essential_missions_identified
	msg := "CP-2: Contingency plan does not identify essential missions and business functions"
}

deny_no_recovery_objectives contains msg if {
	input.normalized_data.contingency_plan
	not input.normalized_data.contingency_plan.recovery_objectives_defined
	msg := "CP-2: Recovery time objectives (RTO) and recovery point objectives (RPO) are not defined"
}

deny_no_roles_responsibilities contains msg if {
	input.normalized_data.contingency_plan
	not input.normalized_data.contingency_plan.roles_assigned
	msg := "CP-2: Contingency plan does not assign roles and responsibilities"
}

deny_no_contact_list contains msg if {
	input.normalized_data.contingency_plan
	not input.normalized_data.contingency_plan.contact_list_current
	msg := "CP-2: Contingency plan contact list is not current"
}

deny_plan_not_distributed contains msg if {
	input.normalized_data.contingency_plan
	not input.normalized_data.contingency_plan.distributed_to_personnel
	msg := "CP-2: Contingency plan has not been distributed to key personnel"
}

deny_no_system_inventory contains msg if {
	input.normalized_data.contingency_plan
	not input.normalized_data.contingency_plan.system_inventory_included
	msg := "CP-2: Contingency plan does not include critical system component inventory"
}

default compliant := false

compliant if {
	count(deny_no_contingency_plan) == 0
	count(deny_plan_not_reviewed) == 0
	count(deny_no_essential_missions) == 0
	count(deny_no_recovery_objectives) == 0
	count(deny_no_roles_responsibilities) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_contingency_plan],
		[f | some f in deny_plan_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_essential_missions],
		array.concat(
			[f | some f in deny_no_recovery_objectives],
			array.concat(
				[f | some f in deny_no_roles_responsibilities],
				array.concat(
					[f | some f in deny_no_contact_list],
					array.concat(
						[f | some f in deny_plan_not_distributed],
						[f | some f in deny_no_system_inventory],
					),
				),
			),
		),
	),
)

result := {
	"control_id": "CP-2",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
