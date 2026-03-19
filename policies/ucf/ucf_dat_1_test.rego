package ucf.dat.ucf_dat_1_test

import rego.v1

import data.ucf.dat.ucf_dat_1

test_encrypted_buckets if {
	result := ucf_dat_1.result with input as {"normalized_data": {
		"storage_buckets": [
			{"name": "bucket-1", "encryption": {"SSEAlgorithm": "aws:kms"}},
		],
	}}
	result.compliant == true
}

test_unencrypted_bucket if {
	result := ucf_dat_1.result with input as {"normalized_data": {
		"storage_buckets": [
			{"name": "bucket-1"},
		],
	}}
	result.compliant == false
}
