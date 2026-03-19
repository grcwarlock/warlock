package nist.ir.ir_8

import rego.v1

# IR-8: Incident Response Plan
# Validates incident response plan is documented and maintained

deny_no_ir_plan contains msg if {
	not input.normalized_data.ir_plan
	msg := "IR-8: No incident response plan exists"
}

deny_plan_not_reviewed contains msg if {
	input.normalized_data.ir_plan
	input.normalized_data.ir_plan.last_review_days > 365
	msg := sprintf("IR-8: Incident response plan has not been reviewed in %d days (exceeds annual requirement)", [input.normalized_data.ir_plan.last_review_days])
}

deny_no_mission_structure contains msg if {
	input.normalized_data.ir_plan
	not input.normalized_data.ir_plan.organizational_structure_defined
	msg := "IR-8: Incident response plan does not define organizational structure for IR capability"
}

deny_no_roles_defined contains msg if {
	input.normalized_data.ir_plan
	not input.normalized_data.ir_plan.roles_responsibilities_defined
	msg := "IR-8: Incident response plan does not define roles and responsibilities"
}

deny_no_incident_categories contains msg if {
	input.normalized_data.ir_plan
	not input.normalized_data.ir_plan.incident_categories_defined
	msg := "IR-8: Incident response plan does not define incident categories and severity levels"
}

deny_no_metrics contains msg if {
	input.normalized_data.ir_plan
	not input.normalized_data.ir_plan.metrics_defined
	msg := "IR-8: Incident response plan does not define metrics for measuring IR capability"
}

deny_plan_not_distributed contains msg if {
	input.normalized_data.ir_plan
	not input.normalized_data.ir_plan.distributed_to_personnel
	msg := "IR-8: Incident response plan has not been distributed to IR team members"
}

deny_no_plan_alignment contains msg if {
	input.normalized_data.ir_plan
	not input.normalized_data.ir_plan.aligned_with_contingency_plan
	msg := "IR-8: Incident response plan is not aligned with the contingency plan"
}

default compliant := false

compliant if {
	count(deny_no_ir_plan) == 0
	count(deny_plan_not_reviewed) == 0
	count(deny_no_roles_defined) == 0
	count(deny_no_incident_categories) == 0
	count(deny_plan_not_distributed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ir_plan],
		[f | some f in deny_plan_not_reviewed],
	),
	array.concat(
		[f | some f in deny_no_mission_structure],
		array.concat(
			[f | some f in deny_no_roles_defined],
			array.concat(
				[f | some f in deny_no_incident_categories],
				array.concat(
					[f | some f in deny_no_metrics],
					array.concat(
						[f | some f in deny_plan_not_distributed],
						[f | some f in deny_no_plan_alignment],
					),
				),
			),
		),
	),
)

result := {
	"control_id": "IR-8",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
