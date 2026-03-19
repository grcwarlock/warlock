package nist.ra.ra_9

import rego.v1

# RA-9: Criticality Analysis

deny_no_criticality_analysis contains msg if {
	not input.normalized_data.criticality_analysis
	msg := "RA-9: No criticality analysis performed for organizational systems"
}

deny_analysis_outdated contains msg if {
	ca := input.normalized_data.criticality_analysis
	ca.last_review_days > 365
	msg := sprintf("RA-9: Criticality analysis has not been reviewed in %d days", [ca.last_review_days])
}

deny_system_no_criticality contains msg if {
	some system in input.normalized_data.system_inventory.systems
	not system.criticality_level
	msg := sprintf("RA-9: System '%s' does not have a criticality level assigned", [system.name])
}

deny_no_mission_mapping contains msg if {
	ca := input.normalized_data.criticality_analysis
	not ca.mission_mapping_completed
	msg := "RA-9: Systems have not been mapped to mission and business functions for criticality determination"
}

deny_no_dependencies_identified contains msg if {
	ca := input.normalized_data.criticality_analysis
	not ca.dependencies_identified
	msg := "RA-9: Critical system dependencies and interdependencies have not been identified"
}

default compliant := false

compliant if {
	count(deny_no_criticality_analysis) == 0
	count(deny_analysis_outdated) == 0
	count(deny_system_no_criticality) == 0
	count(deny_no_mission_mapping) == 0
	count(deny_no_dependencies_identified) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_criticality_analysis],
		[f | some f in deny_analysis_outdated],
	),
	array.concat(
		[f | some f in deny_system_no_criticality],
		array.concat(
			[f | some f in deny_no_mission_mapping],
			[f | some f in deny_no_dependencies_identified],
		),
	),
)

result := {
	"control_id": "RA-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
