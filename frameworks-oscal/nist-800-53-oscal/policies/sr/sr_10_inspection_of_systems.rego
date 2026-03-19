package nist.sr.sr_10

import rego.v1

# SR-10: Inspection of Systems or Components

deny_no_inspection_process contains msg if {
	not input.normalized_data.system_inspection
	msg := "SR-10: No process for inspection of systems or components upon delivery"
}

deny_no_inspection_schedule contains msg if {
	si := input.normalized_data.system_inspection
	not si.schedule_defined
	msg := "SR-10: No inspection schedule defined for system components"
}

deny_component_not_inspected contains msg if {
	some component in input.normalized_data.delivered_components
	not component.inspection_completed
	msg := sprintf("SR-10: Delivered component '%s' has not been inspected", [component.name])
}

deny_inspection_findings_open contains msg if {
	some finding in input.normalized_data.inspection_findings
	finding.status == "open"
	finding.days_open > 30
	msg := sprintf("SR-10: Inspection finding '%s' has been open for %d days", [finding.id, finding.days_open])
}

deny_no_random_inspections contains msg if {
	si := input.normalized_data.system_inspection
	not si.random_inspections_conducted
	msg := "SR-10: No random or unpredictable inspections conducted"
}

default compliant := false

compliant if {
	count(deny_no_inspection_process) == 0
	count(deny_no_inspection_schedule) == 0
	count(deny_component_not_inspected) == 0
	count(deny_inspection_findings_open) == 0
	count(deny_no_random_inspections) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_inspection_process],
		[f | some f in deny_no_inspection_schedule],
	),
	array.concat(
		[f | some f in deny_component_not_inspected],
		array.concat(
			[f | some f in deny_inspection_findings_open],
			[f | some f in deny_no_random_inspections],
		),
	),
)

result := {
	"control_id": "SR-10",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
