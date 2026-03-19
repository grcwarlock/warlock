package iso_27001.a8.a8_03_test

import rego.v1

import data.iso_27001.a8.a8_03

test_compliant_a8_03 if {
	result := a8_03.result with input as {"normalized_data": {
		"s3": {
			"account_public_access_blocked": true,
			"buckets": [],
		},
		"config": {
			"s3_public_read_prohibited_rule_exists": true,
		},
		"kms": {
			"keys": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_03 if {
	result := a8_03.result with input as {"normalized_data": {}}
	result.compliant == false
}
