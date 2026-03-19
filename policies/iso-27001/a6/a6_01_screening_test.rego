package iso_27001.a6.a6_01_test

import rego.v1

import data.iso_27001.a6.a6_01

test_compliant_a6_01 if {
	result := a6_01.result with input as {"normalized_data": {
		"config": {
			"screening_tag_rule_exists": true,
		},
		"policies": {
			"screening_process_documented": true,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_01 if {
	result := a6_01.result with input as {"normalized_data": {}}
	result.compliant == false
}
