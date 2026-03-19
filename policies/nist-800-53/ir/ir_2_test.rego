package nist.ir.ir_2_test

import rego.v1

import data.nist.ir.ir_2

test_compliant_ir_training if {
	result := ir_2.result with input as {"normalized_data": {
		"ir_training": {"system_change_detected": false, "retraining_completed": true, "curriculum_defined": true},
		"users": [
			{"username": "alice", "ir_role_assigned": true, "ir_training_completed": true, "ir_training_days": 100, "role_assignment_days": 365},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_ir_training if {
	result := ir_2.result with input as {"normalized_data": {
		"users": [
			{"username": "bob", "ir_role_assigned": true, "ir_training_completed": false, "role_assignment_days": 365},
		],
	}}
	result.compliant == false
}
