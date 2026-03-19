package nist.mp.mp_5

import rego.v1

# MP-5: Media Transport

deny_unencrypted_transport contains msg if {
	some transport in input.normalized_data.media_protection.transport_events
	transport.contains_sensitive_data
	not transport.encrypted
	msg := sprintf("MP-5: Media transport event '%s' carries sensitive data without encryption", [transport.transport_id])
}

deny_no_custodian contains msg if {
	some transport in input.normalized_data.media_protection.transport_events
	transport.contains_sensitive_data
	not transport.custodian_assigned
	msg := sprintf("MP-5: Sensitive media transport '%s' has no assigned custodian", [transport.transport_id])
}

deny_no_tracking contains msg if {
	some transport in input.normalized_data.media_protection.transport_events
	not transport.tracked
	msg := sprintf("MP-5: Media transport event '%s' is not being tracked", [transport.transport_id])
}

deny_unauthorized_courier contains msg if {
	some transport in input.normalized_data.media_protection.transport_events
	transport.contains_sensitive_data
	not transport.courier_authorized
	msg := sprintf("MP-5: Media transport '%s' uses an unauthorized courier service", [transport.transport_id])
}

default compliant := false

compliant if {
	count(deny_unencrypted_transport) == 0
	count(deny_no_custodian) == 0
	count(deny_no_tracking) == 0
	count(deny_unauthorized_courier) == 0
}

findings := array.concat(
	array.concat(
		[f | some f in deny_unencrypted_transport],
		[f | some f in deny_no_custodian],
	),
	array.concat(
		[f | some f in deny_no_tracking],
		[f | some f in deny_unauthorized_courier],
	),
)

result := {
	"control_id": "MP-5",
	"compliant": compliant,
	"findings": findings,
	"severity": "high",
}
