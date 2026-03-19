package hipaa.s164_310.s164_310_d_1_test

import rego.v1

import data.hipaa.s164_310.s164_310_d_1

test_compliant_device_media if {
	result := s164_310_d_1.result with input as {"normalized_data": {
		"policies": {
			"media_disposal_policy": true,
			"media_reuse_procedure": true,
		},
		"resources": {"media_devices": [
			{"name": "usb-001", "removable": true, "encrypted": true},
		]},
		"config": {"hardware_inventory_maintained": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_unencrypted_removable_media if {
	result := s164_310_d_1.result with input as {"normalized_data": {
		"policies": {
			"media_disposal_policy": true,
			"media_reuse_procedure": true,
		},
		"resources": {"media_devices": [
			{"name": "usb-001", "removable": true, "encrypted": false},
		]},
		"config": {"hardware_inventory_maintained": true},
	}}
	result.compliant == false
}
