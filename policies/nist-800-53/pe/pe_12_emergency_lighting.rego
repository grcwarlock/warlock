package nist.pe.pe_12

import rego.v1

# PE-12: Emergency Lighting

deny_no_emergency_lighting contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.emergency_lighting_installed
	msg := sprintf("PE-12: Facility '%s' does not have emergency lighting installed", [facility.facility_id])
}

deny_emergency_lighting_not_tested contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.emergency_lighting_installed
	not facility.emergency_lighting_tested_within_365_days
	msg := sprintf("PE-12: Emergency lighting at facility '%s' has not been tested within the last 365 days", [facility.facility_id])
}

deny_insufficient_coverage contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.emergency_lighting_installed
	not facility.emergency_lighting_covers_exits
	msg := sprintf("PE-12: Emergency lighting at facility '%s' does not cover all emergency exits and evacuation routes", [facility.facility_id])
}

default compliant := false

compliant if {
	count(deny_no_emergency_lighting) == 0
	count(deny_emergency_lighting_not_tested) == 0
	count(deny_insufficient_coverage) == 0
}

findings := array.concat(
	[f | some f in deny_no_emergency_lighting],
	array.concat(
		[f | some f in deny_emergency_lighting_not_tested],
		[f | some f in deny_insufficient_coverage],
	),
)

result := {
	"control_id": "PE-12",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
