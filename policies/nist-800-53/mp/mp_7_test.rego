package nist.mp.mp_7_test

import rego.v1

import data.nist.mp.mp_7

test_compliant_media_use if {
	result := mp_7.result with input as {"normalized_data": {
		"media_protection": {
			"removable_media_policy_defined": true,
			"active_media": [
				{"asset_id": "MA-001", "removable": false, "media_type": "ssd", "connected_system": "srv-01", "encrypted": true, "scanned_for_malware": true},
			],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_prohibited_media if {
	result := mp_7.result with input as {"normalized_data": {
		"media_protection": {
			"removable_media_policy_defined": true,
			"active_media": [
				{"asset_id": "MA-002", "removable": true, "media_type": "usb_flash_drive", "connected_system": "srv-02", "exemption_granted": false, "encrypted": false, "scanned_for_malware": false},
			],
		},
	}}
	result.compliant == false
}
