package iso_27001.a8.a8_15_test

import rego.v1

import data.iso_27001.a8.a8_15

test_compliant_a8_15 if {
	result := a8_15.result with input as {"normalized_data": {
		"cloudtrail": {
			"enabled": true,
			"is_multi_region": true,
			"log_file_validation_enabled": true,
		},
		"vpcs": [],
		"s3": {
			"buckets": [],
		},
		"cloudwatch": {
			"log_groups": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_15 if {
	result := a8_15.result with input as {"normalized_data": {}}
	result.compliant == false
}
