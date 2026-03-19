package nist.cp.cp_4_test

import rego.v1

import data.nist.cp.cp_4

test_compliant_plan_testing if {
	result := cp_4.result with input as {"normalized_data": {
		"contingency_plan_testing": {
			"last_test_days": 180,
			"results_documented": true,
			"open_deficiencies": 0,
			"tabletop_exercise_conducted": true,
			"plan_updated_after_test": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_testing if {
	result := cp_4.result with input as {"normalized_data": {}}
	result.compliant == false
}
