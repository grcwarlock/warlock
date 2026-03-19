package iso_27001.a8.a8_13_test

import rego.v1

import data.iso_27001.a8.a8_13

test_compliant_a8_13 if {
	result := a8_13.result with input as {"normalized_data": {
		"backup": {
			"restore_testing_plan_exists": true,
			"plans": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_13 if {
	result := a8_13.result with input as {"normalized_data": {
		"backup": {
			"plans": [],
			"recovery_point_count": 0,
			"restore_testing_plan_exists": false,
		},
	}}
	result.compliant == false
}
