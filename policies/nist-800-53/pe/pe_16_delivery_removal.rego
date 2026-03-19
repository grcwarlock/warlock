package nist.pe.pe_16

import rego.v1

# PE-16: Delivery and Removal

deny_no_asset_tracking contains msg if {
	not input.normalized_data.physical_security.asset_tracking_system
	msg := "PE-16: Organization does not have an asset tracking system for deliveries and removals"
}

deny_unlogged_delivery contains msg if {
	some event in input.normalized_data.physical_security.delivery_removal_events
	event.event_type == "delivery"
	not event.logged
	msg := sprintf("PE-16: Delivery event '%s' at facility '%s' was not logged", [event.event_id, event.facility_id])
}

deny_unlogged_removal contains msg if {
	some event in input.normalized_data.physical_security.delivery_removal_events
	event.event_type == "removal"
	not event.logged
	msg := sprintf("PE-16: Equipment removal event '%s' at facility '%s' was not logged", [event.event_id, event.facility_id])
}

deny_removal_not_authorized contains msg if {
	some event in input.normalized_data.physical_security.delivery_removal_events
	event.event_type == "removal"
	not event.authorized
	msg := sprintf("PE-16: Equipment removal '%s' was not authorized before removal from facility '%s'", [event.event_id, event.facility_id])
}

deny_no_receiving_inspection contains msg if {
	some event in input.normalized_data.physical_security.delivery_removal_events
	event.event_type == "delivery"
	not event.inspected_on_receipt
	msg := sprintf("PE-16: Delivery '%s' was not inspected upon receipt at facility '%s'", [event.event_id, event.facility_id])
}

default compliant := false

compliant if {
	count(deny_no_asset_tracking) == 0
	count(deny_unlogged_delivery) == 0
	count(deny_unlogged_removal) == 0
	count(deny_removal_not_authorized) == 0
	count(deny_no_receiving_inspection) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_no_asset_tracking],
		[f | some f in deny_unlogged_delivery],
	),
	array.concat(
		array.concat(
			[f | some f in deny_unlogged_removal],
			[f | some f in deny_removal_not_authorized],
		),
		[f | some f in deny_no_receiving_inspection],
	),
)

result := {
	"control_id": "PE-16",
	"compliant": compliant,
	"findings": findings,
	"severity": "medium",
}
