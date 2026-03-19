package nist.mp.mp_4_test

import rego.v1

import data.nist.mp.mp_4

test_compliant_media_storage if {
	result := mp_4.result with input as {"normalized_data": {
		"media_protection": {
			"media_inventory_maintained": true,
			"media_assets": [
				{"asset_id": "MA-001", "contains_sensitive_data": true, "stored_securely": true, "digital": true, "encrypted_at_rest": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unsecured if {
	result := mp_4.result with input as {"normalized_data": {
		"media_protection": {
			"media_inventory_maintained": false,
			"media_assets": [
				{"asset_id": "MA-002", "contains_sensitive_data": true, "stored_securely": false, "digital": true, "encrypted_at_rest": false},
			],
		},
	}}
	result.compliant == false
}
