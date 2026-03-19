package iso_27001.a8.a8_29_test

import rego.v1

import data.iso_27001.a8.a8_29

test_compliant_a8_29 if {
	result := a8_29.result with input as {"normalized_data": {
		"inspector": {
			"enabled": true,
			"ec2_scanning_enabled": true,
			"ecr_scanning_enabled": true,
		},
		"pipelines": [],
		"codebuild": {
			"report_groups": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_29 if {
	result := a8_29.result with input as {"normalized_data": {}}
	result.compliant == false
}
