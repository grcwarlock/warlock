package pci_dss.r3_test

import rego.v1

import data.pci_dss.r3

test_compliant_storage if {
	result := r3.result with input as {"normalized_data": {
		"data_stores": [{"name": "s3-cardholder", "encryption_enabled": true, "contains_pan": true, "pan_protected": true}],
		"encryption_keys": [{"id": "key-1", "rotation_enabled": true}],
	}}
	result.compliant == true
}

test_noncompliant_no_encryption if {
	result := r3.result with input as {"normalized_data": {
		"data_stores": [{"name": "s3-data", "encryption_enabled": false, "contains_pan": false, "pan_protected": false}],
		"encryption_keys": [],
	}}
	result.compliant == false
}
