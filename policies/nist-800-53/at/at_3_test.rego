package nist.at.at_3_test

import rego.v1

import data.nist.at.at_3

test_compliant_role_based_training if {
	result := at_3.result with input as {"normalized_data": {
		"role_based_training": {"curriculum_defined": true},
		"users": [
			{"username": "alice", "role": "admin", "role_based_training_completed": true, "role_training_completion_days": 100, "privileged_access": true, "privileged_role_training_completed": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_admin_no_training if {
	result := at_3.result with input as {"normalized_data": {
		"role_based_training": {"curriculum_defined": true},
		"users": [
			{"username": "bob", "role": "admin", "role_based_training_completed": false, "privileged_access": false},
		],
	}}
	result.compliant == false
}
