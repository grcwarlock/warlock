package nist.mp.mp_5_test

import rego.v1

import data.nist.mp.mp_5

test_compliant_media_transport if {
	result := mp_5.result with input as {"normalized_data": {
		"media_protection": {
			"transport_events": [
				{"transport_id": "MT-001", "contains_sensitive_data": true, "encrypted": true, "custodian_assigned": true, "tracked": true, "courier_authorized": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unencrypted_transport if {
	result := mp_5.result with input as {"normalized_data": {
		"media_protection": {
			"transport_events": [
				{"transport_id": "MT-002", "contains_sensitive_data": true, "encrypted": false, "custodian_assigned": false, "tracked": false, "courier_authorized": false},
			],
		},
	}}
	result.compliant == false
}
