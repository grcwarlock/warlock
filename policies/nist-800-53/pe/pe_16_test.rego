package nist.pe.pe_16_test

import rego.v1

import data.nist.pe.pe_16

test_compliant if {
	result := pe_16.result with input as {"normalized_data": {"physical_security": {"asset_tracking_system": true, "delivery_removal_events": [{"event_id": "EV-1", "facility_id": "DC-1", "event_type": "delivery", "logged": true, "authorized": true, "inspected_on_receipt": true}]}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant if {
	result := pe_16.result with input as {"normalized_data": {"physical_security": {"delivery_removal_events": [{"event_id": "EV-2", "facility_id": "DC-2", "event_type": "delivery", "logged": false, "inspected_on_receipt": false}]}}}
	result.compliant == false
}
