package cmmc.pe.pe_l2_3_10_1

import rego.v1

# PE.L2-3.10.1: Physical Access Control
# Limit physical access to organizational systems, equipment, and operating environments to authorized individuals

deny_no_physical_access_controls contains msg if {
	some facility in input.normalized_data.facilities
	not facility.physical_access_controls_implemented
	msg := sprintf("PE.L2-3.10.1: Facility '%s' does not have physical access controls implemented", [facility.name])
}

deny_no_visitor_logs contains msg if {
	some facility in input.normalized_data.facilities
	not facility.visitor_log_maintained
	msg := sprintf("PE.L2-3.10.1: Facility '%s' does not maintain visitor access logs", [facility.name])
}

deny_no_access_review contains msg if {
	some facility in input.normalized_data.facilities
	facility.physical_access_controls_implemented
	facility.last_access_list_review_days > 90
	msg := sprintf("PE.L2-3.10.1: Facility '%s' physical access list has not been reviewed in %d days", [facility.name, facility.last_access_list_review_days])
}

default compliant := false

compliant if {
	count(deny_no_physical_access_controls) == 0
	count(deny_no_visitor_logs) == 0
	count(deny_no_access_review) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_physical_access_controls],
		[f | some f in deny_no_visitor_logs],
	),
	[f | some f in deny_no_access_review],
)

result := {
	"control_id": "PE.L2-3.10.1",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
