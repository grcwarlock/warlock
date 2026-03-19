package iso_27001.a5.a5_33_test

import rego.v1

import data.iso_27001.a5.a5_33

test_compliant_a5_33 if {
	result := a5_33.result with input as {"normalized_data": {
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_33 if {
	result := a5_33.result with input as {"normalized_data": {
		"s3": {"buckets": [{
			"name": "records-bucket",
			"purpose": "records",
			"versioning_enabled": false,
			"encryption_enabled": false,
			"object_lock_enabled": false,
			"access_logging_enabled": false,
		}]},
	}}
	result.compliant == false
}
