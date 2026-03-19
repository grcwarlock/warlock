package iso_27001.a5.a5_09_test

import rego.v1

import data.iso_27001.a5.a5_09

test_compliant_a5_09 if {
	result := a5_09.result with input as {"normalized_data": {
		"config": {
			"recorder_enabled": true,
			"required_tags_rule_exists": true,
		},
		"resources": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_09 if {
	result := a5_09.result with input as {"normalized_data": {}}
	result.compliant == false
}
