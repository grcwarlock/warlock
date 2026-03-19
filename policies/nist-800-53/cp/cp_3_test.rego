package nist.cp.cp_3_test

import rego.v1

import data.nist.cp.cp_3

test_compliant_contingency_training if {
	result := cp_3.result with input as {"normalized_data": {
		"contingency_training": {"system_change_detected": false, "retraining_completed": true},
		"users": [
			{"username": "alice", "contingency_role_assigned": true, "contingency_training_completed": true, "contingency_training_days": 100, "role_assignment_days": 365},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_training if {
	result := cp_3.result with input as {"normalized_data": {
		"users": [
			{"username": "bob", "contingency_role_assigned": true, "contingency_training_completed": false, "role_assignment_days": 365},
		],
	}}
	result.compliant == false
}
