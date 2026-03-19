package nist.pm.pm_4

import rego.v1

# PM-4: Plan of Action and Milestones Process

deny_no_poam_process contains msg if {
	not input.normalized_data.poam_process
	msg := "PM-4: No plan of action and milestones (POA&M) process established"
}

deny_poam_no_milestones contains msg if {
	some poam in input.normalized_data.poams
	not poam.has_milestones
	msg := sprintf("PM-4: POA&M for system '%s' does not include milestones", [poam.system_name])
}

deny_poam_overdue contains msg if {
	some poam in input.normalized_data.poams
	some item in poam.items
	item.status == "open"
	item.days_past_due > 0
	msg := sprintf("PM-4: POA&M item '%s' for system '%s' is %d days overdue", [item.finding_id, poam.system_name, item.days_past_due])
}

deny_poam_not_reviewed contains msg if {
	process := input.normalized_data.poam_process
	process.last_review_days > 30
	msg := sprintf("PM-4: POA&M process has not been reviewed in %d days (exceeds 30-day requirement)", [process.last_review_days])
}

deny_poam_no_reporting contains msg if {
	process := input.normalized_data.poam_process
	not process.reporting_to_leadership
	msg := "PM-4: POA&M findings are not reported to senior leadership"
}

deny_critical_findings_no_poam contains msg if {
	some finding in input.normalized_data.security_findings
	finding.severity == "critical"
	not finding.tracked_in_poam
	msg := sprintf("PM-4: Critical finding '%s' is not tracked in a POA&M", [finding.id])
}

default compliant := false

compliant if {
	count(deny_no_poam_process) == 0
	count(deny_poam_no_milestones) == 0
	count(deny_poam_overdue) == 0
	count(deny_poam_not_reviewed) == 0
	count(deny_poam_no_reporting) == 0
	count(deny_critical_findings_no_poam) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_poam_process],
		[f | some f in deny_poam_no_milestones],
	),
	array.concat(
		array.concat(
			[f | some f in deny_poam_overdue],
			[f | some f in deny_poam_not_reviewed],
		),
		array.concat(
			[f | some f in deny_poam_no_reporting],
			[f | some f in deny_critical_findings_no_poam],
		),
	),
)

result := {
	"control_id": "PM-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
