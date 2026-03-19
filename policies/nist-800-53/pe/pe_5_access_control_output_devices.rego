package nist.pe.pe_5

import rego.v1

# PE-5: Access Control for Output Devices

deny_uncontrolled_output_device contains msg if {
	some device in input.normalized_data.physical_security.output_devices
	not device.access_controlled
	msg := sprintf("PE-5: Output device '%s' (%s) does not have physical access controls", [device.device_id, device.device_type])
}

deny_public_area_output contains msg if {
	some device in input.normalized_data.physical_security.output_devices
	device.in_public_area
	device.handles_sensitive_output
	msg := sprintf("PE-5: Output device '%s' handles sensitive output but is located in a public area", [device.device_id])
}

deny_no_pickup_authentication contains msg if {
	some device in input.normalized_data.physical_security.output_devices
	device.shared
	not device.requires_authentication_for_pickup
	msg := sprintf("PE-5: Shared output device '%s' does not require authentication for output pickup", [device.device_id])
}

default compliant := false

compliant if {
	count(deny_uncontrolled_output_device) == 0
	count(deny_public_area_output) == 0
	count(deny_no_pickup_authentication) == 0
}

findings := array.concat(
	[f | some f in deny_uncontrolled_output_device],
	array.concat(
		[f | some f in deny_public_area_output],
		[f | some f in deny_no_pickup_authentication],
	),
)

result := {
	"control_id": "PE-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
