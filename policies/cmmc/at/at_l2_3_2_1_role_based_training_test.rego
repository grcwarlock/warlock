package cmmc.at.at_l2_3_2_1_test

import rego.v1

import data.cmmc.at.at_l2_3_2_1

test_compliant_role_based_training if {
	result := at_l2_3_2_1.result with input as {"normalized_data": {"users": [
		{"username": "alice", "enabled": true, "security_training_completed": true, "training_age_days": 30, "privileged": true, "role_specific_training_completed": true},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_security_training if {
	result := at_l2_3_2_1.result with input as {"normalized_data": {"users": [
		{"username": "bob", "enabled": true, "security_training_completed": false, "training_age_days": 0, "privileged": false, "role_specific_training_completed": false},
	]}}
	result.compliant == false
}
