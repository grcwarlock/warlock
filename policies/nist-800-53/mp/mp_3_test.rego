package nist.mp.mp_3_test

import rego.v1

import data.nist.mp.mp_3

test_compliant_media_marking if {
	result := mp_3.result with input as {"normalized_data": {
		"media_protection": {
			"media_assets": [
				{"asset_id": "MA-001", "media_type": "usb", "classification_label": "confidential", "contains_sensitive_data": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unmarked if {
	result := mp_3.result with input as {"normalized_data": {
		"media_protection": {
			"media_assets": [
				{"asset_id": "MA-002", "media_type": "disk", "contains_sensitive_data": true},
			],
		},
	}}
	result.compliant == false
}
