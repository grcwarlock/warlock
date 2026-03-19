package nist.pm.pm_1

import rego.v1

# PM-1: Information Security Program Plan

deny_no_program_plan contains msg if {
	not input.normalized_data.security_program_plan
	msg := "PM-1: No information security program plan documented"
}

deny_plan_not_approved contains msg if {
	plan := input.normalized_data.security_program_plan
	not plan.approved
	msg := "PM-1: Information security program plan has not been approved by authorizing official"
}

deny_plan_outdated contains msg if {
	plan := input.normalized_data.security_program_plan
	plan.last_review_days > 365
	msg := sprintf("PM-1: Information security program plan has not been reviewed in %d days (exceeds 365-day requirement)", [plan.last_review_days])
}

deny_plan_missing_scope contains msg if {
	plan := input.normalized_data.security_program_plan
	not plan.defines_scope
	msg := "PM-1: Program plan does not define the scope of the information security program"
}

deny_plan_missing_roles contains msg if {
	plan := input.normalized_data.security_program_plan
	not plan.defines_roles_responsibilities
	msg := "PM-1: Program plan does not define roles and responsibilities for information security"
}

deny_plan_not_distributed contains msg if {
	plan := input.normalized_data.security_program_plan
	not plan.distributed_to_stakeholders
	msg := "PM-1: Program plan has not been distributed to relevant stakeholders"
}

default compliant := false

compliant if {
	count(deny_no_program_plan) == 0
	count(deny_plan_not_approved) == 0
	count(deny_plan_outdated) == 0
	count(deny_plan_missing_scope) == 0
	count(deny_plan_missing_roles) == 0
	count(deny_plan_not_distributed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_program_plan],
		[f | some f in deny_plan_not_approved],
	),
	array.concat(
		array.concat(
			[f | some f in deny_plan_outdated],
			[f | some f in deny_plan_missing_scope],
		),
		array.concat(
			[f | some f in deny_plan_missing_roles],
			[f | some f in deny_plan_not_distributed],
		),
	),
)

result := {
	"control_id": "PM-1",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
