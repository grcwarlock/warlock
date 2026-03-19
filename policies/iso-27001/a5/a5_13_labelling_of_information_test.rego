package iso_27001.a5.a5_13_test

import rego.v1

import data.iso_27001.a5.a5_13

test_compliant_a5_13 if {
	result := a5_13.result with input as {"normalized_data": {
		"organization": {
			"tag_policies_enforced": true,
		},
		"config": {
			"required_tags_rule_exists": true,
		},
		"resources": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_13 if {
	result := a5_13.result with input as {"normalized_data": {}}
	result.compliant == false
}
