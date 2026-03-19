package iso_27001.a8.a8_24_test

import rego.v1

import data.iso_27001.a8.a8_24

test_compliant_a8_24 if {
	result := a8_24.result with input as {"normalized_data": {
		"config": {
			"encrypted_volumes_rule_exists": true,
		},
		"kms": {
			"keys": ["item1"],
		},
		"ec2": {
			"volumes": [],
		},
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_24 if {
	result := a8_24.result with input as {"normalized_data": {
		"kms": {"keys": []},
		"ec2": {"volumes": [{"id": "vol-123", "encrypted": false}]},
		"s3": {"buckets": []},
		"config": {"encrypted_volumes_rule_exists": false},
	}}
	result.compliant == false
}
