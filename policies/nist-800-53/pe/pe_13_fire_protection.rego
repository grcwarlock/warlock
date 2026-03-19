package nist.pe.pe_13

import rego.v1

# PE-13: Fire Protection

deny_no_fire_detection contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.fire_detection_system_installed
	msg := sprintf("PE-13: Facility '%s' does not have a fire detection system installed", [facility.facility_id])
}

deny_no_fire_suppression contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.contains_critical_systems
	not facility.fire_suppression_system_installed
	msg := sprintf("PE-13: Facility '%s' with critical systems does not have a fire suppression system", [facility.facility_id])
}

deny_fire_system_not_tested contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.fire_detection_system_installed
	not facility.fire_system_tested_within_365_days
	msg := sprintf("PE-13: Fire detection/suppression system at facility '%s' has not been tested within the last 365 days", [facility.facility_id])
}

deny_no_fire_notification contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.fire_detection_system_installed
	not facility.fire_alarm_connected_to_notification
	msg := sprintf("PE-13: Fire alarm at facility '%s' is not connected to an automatic notification system", [facility.facility_id])
}

deny_no_fire_marshal_inspection contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.fire_marshal_inspection_current
	msg := sprintf("PE-13: Facility '%s' does not have a current fire marshal inspection", [facility.facility_id])
}

default compliant := false

compliant if {
	count(deny_no_fire_detection) == 0
	count(deny_no_fire_suppression) == 0
	count(deny_fire_system_not_tested) == 0
	count(deny_no_fire_notification) == 0
	count(deny_no_fire_marshal_inspection) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_fire_detection],
		[f | some f in deny_no_fire_suppression],
	),
	array.concat(
		array.concat(
			[f | some f in deny_fire_system_not_tested],
			[f | some f in deny_no_fire_notification],
		),
		[f | some f in deny_no_fire_marshal_inspection],
	),
)

result := {
	"control_id": "PE-13",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
