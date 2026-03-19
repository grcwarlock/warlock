package nist.pm.pm_3

import rego.v1

# PM-3: Information Security and Privacy Resources

deny_no_resource_planning contains msg if {
	not input.normalized_data.security_resource_plan
	msg := "PM-3: No information security resource planning documented in capital planning process"
}

deny_no_budget_line_item contains msg if {
	plan := input.normalized_data.security_resource_plan
	not plan.discrete_budget_line_item
	msg := "PM-3: Information security not established as a discrete budget line item"
}

deny_budget_not_approved contains msg if {
	plan := input.normalized_data.security_resource_plan
	not plan.budget_approved
	msg := "PM-3: Security resource budget has not been approved"
}

deny_no_staffing_plan contains msg if {
	plan := input.normalized_data.security_resource_plan
	not plan.staffing_plan_documented
	msg := "PM-3: No security staffing plan documented"
}

deny_resource_plan_outdated contains msg if {
	plan := input.normalized_data.security_resource_plan
	plan.last_review_days > 365
	msg := sprintf("PM-3: Security resource plan has not been reviewed in %d days", [plan.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_resource_planning) == 0
	count(deny_no_budget_line_item) == 0
	count(deny_budget_not_approved) == 0
	count(deny_no_staffing_plan) == 0
	count(deny_resource_plan_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_resource_planning],
		[f | some f in deny_no_budget_line_item],
	),
	array.concat(
		[f | some f in deny_budget_not_approved],
		array.concat(
			[f | some f in deny_no_staffing_plan],
			[f | some f in deny_resource_plan_outdated],
		),
	),
)

result := {
	"control_id": "PM-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
