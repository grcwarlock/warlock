package iso_27001.a6.a6_03_test

import rego.v1

import data.iso_27001.a6.a6_03

test_compliant_a6_03 if {
	result := a6_03.result with input as {"normalized_data": {
		"config": {
			"training_tag_rule_exists": true,
			"training_noncompliant_count": 0,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_03 if {
	result := a6_03.result with input as {"normalized_data": {
		"users": [{"username": "testuser", "tags": {}}],
		"config": {"training_tag_rule_exists": false},
	}}
	result.compliant == false
}
