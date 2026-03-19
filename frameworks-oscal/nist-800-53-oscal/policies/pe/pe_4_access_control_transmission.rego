package nist.pe.pe_4

import rego.v1

# PE-4: Access Control for Transmission Medium

deny_unprotected_cabling contains msg if {
	some cable in input.normalized_data.physical_security.transmission_media
	not cable.physically_protected
	msg := sprintf("PE-4: Transmission medium '%s' (%s) is not physically protected", [cable.media_id, cable.media_type])
}

deny_no_conduit contains msg if {
	some cable in input.normalized_data.physical_security.transmission_media
	cable.carries_sensitive_data
	not cable.in_secured_conduit
	msg := sprintf("PE-4: Sensitive transmission medium '%s' is not routed through secured conduit", [cable.media_id])
}

deny_accessible_distribution contains msg if {
	some cable in input.normalized_data.physical_security.transmission_media
	cable.distribution_frame_accessible
	not cable.distribution_frame_locked
	msg := sprintf("PE-4: Distribution frame for transmission medium '%s' is accessible but not locked", [cable.media_id])
}

deny_no_cable_inventory contains msg if {
	not input.normalized_data.physical_security.transmission_media_inventory_maintained
	msg := "PE-4: Organization does not maintain an inventory of transmission media"
}

default compliant := false

compliant if {
	count(deny_unprotected_cabling) == 0
	count(deny_no_conduit) == 0
	count(deny_accessible_distribution) == 0
	count(deny_no_cable_inventory) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unprotected_cabling],
		[f | some f in deny_no_conduit],
	),
	array.concat(
		[f | some f in deny_accessible_distribution],
		[f | some f in deny_no_cable_inventory],
	),
)

result := {
	"control_id": "PE-4",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
