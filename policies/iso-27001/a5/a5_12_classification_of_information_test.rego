package iso_27001.a5.a5_12_test

import rego.v1

import data.iso_27001.a5.a5_12

test_compliant_a5_12 if {
	result := a5_12.result with input as {"normalized_data": {
		"macie": {
			"enabled": true,
			"classification_jobs": ["item1"],
		},
		"config": {
			"classification_tag_rule_exists": true,
		},
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_12 if {
	result := a5_12.result with input as {"normalized_data": {}}
	result.compliant == false
}
