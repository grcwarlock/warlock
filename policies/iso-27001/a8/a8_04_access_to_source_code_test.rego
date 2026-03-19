package iso_27001.a8.a8_04_test

import rego.v1

import data.iso_27001.a8.a8_04

test_compliant_a8_04 if {
	result := a8_04.result with input as {"normalized_data": {
		"codecommit": {
			"approval_rules_configured": true,
			"repositories": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_04 if {
	result := a8_04.result with input as {"normalized_data": {}}
	result.compliant == false
}
