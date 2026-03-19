package nist.pe.pe_3

import rego.v1

# PE-3: Physical Access Control

deny_no_entry_control contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.entry_control_mechanism
	msg := sprintf("PE-3: Facility '%s' does not have entry control mechanisms in place", [facility.facility_id])
}

deny_no_access_logs contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.access_logs_maintained
	msg := sprintf("PE-3: Facility '%s' does not maintain physical access logs", [facility.facility_id])
}

deny_no_guard_or_system contains msg if {
	some entry_point in input.normalized_data.physical_security.entry_points
	not entry_point.guard_posted
	not entry_point.automated_system
	msg := sprintf("PE-3: Entry point '%s' at facility '%s' has neither a guard nor an automated access control system", [entry_point.entry_point_id, entry_point.facility_id])
}

deny_tailgating_controls contains msg if {
	some entry_point in input.normalized_data.physical_security.entry_points
	entry_point.high_security
	not entry_point.anti_tailgating_controls
	msg := sprintf("PE-3: High-security entry point '%s' lacks anti-tailgating controls", [entry_point.entry_point_id])
}

deny_no_lock_mechanism contains msg if {
	some entry_point in input.normalized_data.physical_security.entry_points
	not entry_point.lock_mechanism
	msg := sprintf("PE-3: Entry point '%s' does not have a lock mechanism", [entry_point.entry_point_id])
}

default compliant := false

compliant if {
	count(deny_no_entry_control) == 0
	count(deny_no_access_logs) == 0
	count(deny_no_guard_or_system) == 0
	count(deny_tailgating_controls) == 0
	count(deny_no_lock_mechanism) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_entry_control],
		[f | some f in deny_no_access_logs],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_guard_or_system],
			[f | some f in deny_tailgating_controls],
		),
		[f | some f in deny_no_lock_mechanism],
	),
)

result := {
	"control_id": "PE-3",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
