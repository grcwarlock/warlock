package nist.pe.pe_9

import rego.v1

# PE-9: Power Equipment and Cabling

deny_unprotected_power contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.power_equipment_protected
	msg := sprintf("PE-9: Power equipment at facility '%s' is not physically protected from damage and unauthorized access", [facility.facility_id])
}

deny_power_no_access_control contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	not facility.power_room_access_controlled
	msg := sprintf("PE-9: Power equipment room at facility '%s' does not have access controls", [facility.facility_id])
}

deny_exposed_power_cabling contains msg if {
	some facility in input.normalized_data.physical_security.facilities
	facility.power_cabling_exposed
	msg := sprintf("PE-9: Power cabling at facility '%s' is exposed and vulnerable to tampering", [facility.facility_id])
}

default compliant := false

compliant if {
	count(deny_unprotected_power) == 0
	count(deny_power_no_access_control) == 0
	count(deny_exposed_power_cabling) == 0
}

findings := array.concat(
	[f | some f in deny_unprotected_power],
	array.concat(
		[f | some f in deny_power_no_access_control],
		[f | some f in deny_exposed_power_cabling],
	),
)

result := {
	"control_id": "PE-9",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
