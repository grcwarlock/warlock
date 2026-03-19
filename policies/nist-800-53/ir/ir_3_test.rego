package nist.ir.ir_3_test

import rego.v1

import data.nist.ir.ir_3

test_compliant_ir_testing if {
	result := ir_3.result with input as {"normalized_data": {
		"ir_testing": {
			"last_test_days": 180,
			"results_documented": true,
			"tabletop_exercise_conducted": true,
			"lessons_incorporated": true,
			"coordination_tested": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_ir_testing if {
	result := ir_3.result with input as {"normalized_data": {}}
	result.compliant == false
}
