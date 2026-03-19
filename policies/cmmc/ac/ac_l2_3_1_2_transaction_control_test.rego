package cmmc.ac.ac_l2_3_1_2_test

import rego.v1

import data.cmmc.ac.ac_l2_3_1_2

test_compliant_transaction_control if {
	result := ac_l2_3_1_2.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "rbac_enabled": true},
		],
		"iam_policies": [
			{"name": "readonly-policy", "effect": "Allow", "action": "s3:GetObject", "resource": "arn:aws:s3:::bucket/*"},
		],
		"users": [
			{"username": "alice", "admin_access": false, "data_access": true, "separation_of_duties": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_overly_permissive_policy if {
	result := ac_l2_3_1_2.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "rbac_enabled": true},
		],
		"iam_policies": [
			{"name": "admin-all", "effect": "Allow", "action": "*", "resource": "*"},
		],
		"users": [
			{"username": "alice", "admin_access": false, "data_access": true, "separation_of_duties": true},
		],
	}}
	result.compliant == false
}
