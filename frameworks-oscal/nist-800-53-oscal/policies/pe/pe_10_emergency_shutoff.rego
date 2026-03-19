package nist.pe.pe_10

import rego.v1

# PE-10: Emergency Shutoff

deny_no_emergency_shutoff contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.emergency_shutoff_capability
	msg := sprintf("PE-10: Facility '%s' does not have emergency power shutoff capability", [facility.facility_id])
}

deny_shutoff_not_accessible contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.emergency_shutoff_capability
	not facility.emergency_shutoff_accessible
	msg := sprintf("PE-10: Emergency shutoff controls at facility '%s' are not readily accessible to authorized personnel", [facility.facility_id])
}

deny_shutoff_not_tested contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.emergency_shutoff_capability
	not facility.emergency_shutoff_tested_within_365_days
	msg := sprintf("PE-10: Emergency shutoff at facility '%s' has not been tested within the last 365 days", [facility.facility_id])
}

default compliant := false

compliant if {
	count(deny_no_emergency_shutoff) == 0
	count(deny_shutoff_not_accessible) == 0
	count(deny_shutoff_not_tested) == 0
}

findings := array.concat(
	[f | some f in deny_no_emergency_shutoff],
	array.concat(
		[f | some f in deny_shutoff_not_accessible],
		[f | some f in deny_shutoff_not_tested],
	),
)

result := {
	"control_id": "PE-10",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
