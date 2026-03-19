package iso_27001.a5.a5_30_test

import rego.v1

import data.iso_27001.a5.a5_30

test_compliant_a5_30 if {
	result := a5_30.result with input as {"normalized_data": {
		"backup": {
			"restore_testing_plan_exists": true,
			"plans": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_30 if {
	result := a5_30.result with input as {"normalized_data": {
		"backup": {
			"plans": [],
			"restore_testing_plan_exists": false,
			"recovery_point_count": 0,
		},
	}}
	result.compliant == false
}
