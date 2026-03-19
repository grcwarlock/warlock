package nist.pm.pm_11

import rego.v1

# PM-11: Mission and Business Process Definition

deny_no_mission_processes contains msg if {
	not input.normalized_data.mission_business_processes
	msg := "PM-11: Mission and business processes have not been defined with security considerations"
}

deny_no_protection_needs contains msg if {
	some process in input.normalized_data.mission_business_processes.processes
	not process.protection_needs_determined
	msg := sprintf("PM-11: Protection needs not determined for business process '%s'", [process.name])
}

deny_no_risk_determination contains msg if {
	some process in input.normalized_data.mission_business_processes.processes
	not process.risk_determination_completed
	msg := sprintf("PM-11: Risk determination not completed for business process '%s'", [process.name])
}

deny_processes_outdated contains msg if {
	mbp := input.normalized_data.mission_business_processes
	mbp.last_review_days > 365
	msg := sprintf("PM-11: Mission and business process definitions have not been reviewed in %d days", [mbp.last_review_days])
}

default compliant := false

compliant if {
	count(deny_no_mission_processes) == 0
	count(deny_no_protection_needs) == 0
	count(deny_no_risk_determination) == 0
	count(deny_processes_outdated) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_mission_processes],
		[f | some f in deny_no_protection_needs],
	),
	array.concat(
		[f | some f in deny_no_risk_determination],
		[f | some f in deny_processes_outdated],
	),
)

result := {
	"control_id": "PM-11",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
