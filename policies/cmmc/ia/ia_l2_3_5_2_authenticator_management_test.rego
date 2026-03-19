package cmmc.ia.ia_l2_3_5_2_test

import rego.v1

import data.cmmc.ia.ia_l2_3_5_2

test_compliant_authenticator_management if {
	result := ia_l2_3_5_2.result with input as {"normalized_data": {
		"password_policies": [
			{"name": "default", "minimum_length": 14, "expiration_enabled": true},
		],
		"users": [
			{"username": "alice", "enabled": true, "mfa_enabled": true, "access_keys": [
				{"status": "Active", "age_days": 30},
			]},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_weak_password_policy if {
	result := ia_l2_3_5_2.result with input as {"normalized_data": {
		"password_policies": [
			{"name": "default", "minimum_length": 8, "expiration_enabled": true},
		],
		"users": [
			{"username": "alice", "enabled": true, "mfa_enabled": true, "access_keys": []},
		],
	}}
	result.compliant == false
}
