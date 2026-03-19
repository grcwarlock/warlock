package nist.ca.ca_5

import rego.v1

# CA-5: Plan of Action and Milestones
# Validates POA&M management for tracking security weaknesses

deny_no_poam contains msg if {
	not input.normalized_data.poam
	msg := "CA-5: No Plan of Action and Milestones (POA&M) exists"
}

deny_poam_not_updated contains msg if {
	input.normalized_data.poam
	input.normalized_data.poam.last_updated_days > 30
	msg := sprintf("CA-5: POA&M has not been updated in %d days (exceeds 30-day requirement)", [input.normalized_data.poam.last_updated_days])
}

deny_overdue_milestones contains msg if {
	input.normalized_data.poam
	input.normalized_data.poam.overdue_milestones > 0
	msg := sprintf("CA-5: POA&M has %d overdue milestones requiring attention", [input.normalized_data.poam.overdue_milestones])
}

deny_high_risk_items_unaddressed contains msg if {
	some item in input.normalized_data.poam.items
	item.risk_level == "high"
	item.status == "open"
	item.age_days > 30
	msg := sprintf("CA-5: High-risk POA&M item '%s' has been open for %d days", [item.description, item.age_days])
}

deny_no_responsible_party contains msg if {
	some item in input.normalized_data.poam.items
	item.status == "open"
	not item.responsible_party
	msg := sprintf("CA-5: POA&M item '%s' has no responsible party assigned", [item.description])
}

deny_no_completion_dates contains msg if {
	some item in input.normalized_data.poam.items
	item.status == "open"
	not item.scheduled_completion_date
	msg := sprintf("CA-5: POA&M item '%s' has no scheduled completion date", [item.description])
}

default compliant := false

compliant if {
	count(deny_no_poam) == 0
	count(deny_poam_not_updated) == 0
	count(deny_overdue_milestones) == 0
	count(deny_high_risk_items_unaddressed) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_poam],
		[f | some f in deny_poam_not_updated],
	),
	array.concat(
		[f | some f in deny_overdue_milestones],
		array.concat(
			[f | some f in deny_high_risk_items_unaddressed],
			array.concat(
				[f | some f in deny_no_responsible_party],
				[f | some f in deny_no_completion_dates],
			),
		),
	),
)

result := {
	"control_id": "CA-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
