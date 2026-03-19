package nist.pe.pe_11

import rego.v1

# PE-11: Emergency Power

deny_no_ups contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.contains_critical_systems
	not facility.ups_installed
	msg := sprintf("PE-11: Facility '%s' with critical systems does not have an uninterruptible power supply (UPS)", [facility.facility_id])
}

deny_no_generator contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.contains_critical_systems
	not facility.backup_generator_installed
	msg := sprintf("PE-11: Facility '%s' with critical systems does not have a backup generator", [facility.facility_id])
}

deny_ups_not_tested contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.ups_installed
	not facility.ups_tested_within_180_days
	msg := sprintf("PE-11: UPS at facility '%s' has not been tested within the last 180 days", [facility.facility_id])
}

deny_generator_not_tested contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.backup_generator_installed
	not facility.generator_tested_within_90_days
	msg := sprintf("PE-11: Backup generator at facility '%s' has not been tested within the last 90 days", [facility.facility_id])
}

deny_insufficient_runtime contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.ups_installed
	facility.ups_runtime_minutes < 15
	msg := sprintf("PE-11: UPS at facility '%s' provides only %d minutes of runtime, minimum 15 minutes required", [facility.facility_id, facility.ups_runtime_minutes])
}

default compliant := false

compliant if {
	count(deny_no_ups) == 0
	count(deny_no_generator) == 0
	count(deny_ups_not_tested) == 0
	count(deny_generator_not_tested) == 0
	count(deny_insufficient_runtime) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_ups],
		[f | some f in deny_no_generator],
	),
	array.concat(
		array.concat(
			[f | some f in deny_ups_not_tested],
			[f | some f in deny_generator_not_tested],
		),
		[f | some f in deny_insufficient_runtime],
	),
)

result := {
	"control_id": "PE-11",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
