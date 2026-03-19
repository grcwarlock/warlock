package nist.mp.mp_6_test

import rego.v1

import data.nist.mp.mp_6

test_compliant_media_sanitization if {
	result := mp_6.result with input as {"normalized_data": {
		"media_protection": {
			"decommissioned_media": [
				{"asset_id": "MA-001", "sanitized": true, "sanitization_method": "cryptographic_erase", "sanitization_verified": true, "sanitization_record_kept": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_not_sanitized if {
	result := mp_6.result with input as {"normalized_data": {
		"media_protection": {
			"decommissioned_media": [
				{"asset_id": "MA-002", "sanitized": false},
			],
		},
	}}
	result.compliant == false
}
