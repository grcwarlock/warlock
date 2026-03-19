package nist.pe.pe_6

import rego.v1

# PE-6: Monitoring Physical Access

deny_no_surveillance contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.surveillance_system_installed
	msg := sprintf("PE-6: Facility '%s' does not have a surveillance/monitoring system installed", [facility.facility_id])
}

deny_surveillance_not_monitored contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.surveillance_system_installed
	not facility.surveillance_actively_monitored
	msg := sprintf("PE-6: Surveillance system at facility '%s' is not being actively monitored", [facility.facility_id])
}

deny_no_intrusion_detection contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.high_security
	not facility.intrusion_detection_system
	msg := sprintf("PE-6: High-security facility '%s' does not have a physical intrusion detection system", [facility.facility_id])
}

deny_access_logs_not_reviewed contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.access_logs_maintained
	not facility.access_logs_reviewed_regularly
	msg := sprintf("PE-6: Physical access logs for facility '%s' are not reviewed regularly", [facility.facility_id])
}

deny_no_incident_response contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.physical_incident_response_procedure
	msg := sprintf("PE-6: Facility '%s' does not have a physical security incident response procedure", [facility.facility_id])
}

default compliant := false

compliant if {
	count(deny_no_surveillance) == 0
	count(deny_surveillance_not_monitored) == 0
	count(deny_no_intrusion_detection) == 0
	count(deny_access_logs_not_reviewed) == 0
	count(deny_no_incident_response) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_surveillance],
		[f | some f in deny_surveillance_not_monitored],
	),
	array.concat(
		array.concat(
			[f | some f in deny_no_intrusion_detection],
			[f | some f in deny_access_logs_not_reviewed],
		),
		[f | some f in deny_no_incident_response],
	),
)

result := {
	"control_id": "PE-6",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
