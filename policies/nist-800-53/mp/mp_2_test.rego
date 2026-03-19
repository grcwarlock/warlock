package nist.mp.mp_2_test

import rego.v1

import data.nist.mp.mp_2

test_compliant_media_access if {
	result := mp_2.result with input as {"normalized_data": {
		"media_protection": {
			"media_assets": [
				{"asset_id": "MA-001", "media_type": "usb", "access_restricted": true, "contains_sensitive_data": true, "access_list_defined": true},
			],
			"access_events": [
				{"asset_id": "MA-001", "user_id": "alice", "authorized": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_unrestricted if {
	result := mp_2.result with input as {"normalized_data": {
		"media_protection": {
			"media_assets": [
				{"asset_id": "MA-002", "media_type": "usb", "access_restricted": false, "contains_sensitive_data": true, "access_list_defined": false},
			],
			"access_events": [],
		},
	}}
	result.compliant == false
}
