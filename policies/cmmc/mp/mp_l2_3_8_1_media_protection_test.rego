package cmmc.mp.mp_l2_3_8_1_test

import rego.v1

import data.cmmc.mp.mp_l2_3_8_1

test_compliant_media_protection if {
	result := mp_l2_3_8_1.result with input as {"normalized_data": {"storage_resources": [
		{"name": "s3-cui-bucket", "contains_cui": true, "encrypted": true, "publicly_accessible": false, "decommissioned": false, "sanitized": false},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_unencrypted_cui_storage if {
	result := mp_l2_3_8_1.result with input as {"normalized_data": {"storage_resources": [
		{"name": "s3-cui-bucket", "contains_cui": true, "encrypted": false, "publicly_accessible": false, "decommissioned": false, "sanitized": false},
	]}}
	result.compliant == false
}
