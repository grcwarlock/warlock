package ucf.iam.ucf_iam_2_test

import rego.v1

import data.ucf.iam.ucf_iam_2

test_all_mfa_strong_password if {
	result := ucf_iam_2.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "mfa_enabled": true, "access_keys": []},
			{"username": "bob", "mfa_enabled": true, "access_keys": []},
		],
		"password_policy": {"min_length": 14, "max_age_days": 90},
	}}
	result.compliant == true
}

test_user_missing_mfa if {
	result := ucf_iam_2.result with input as {"normalized_data": {
		"users": [{"username": "alice", "mfa_enabled": false, "access_keys": []}],
		"password_policy": {"min_length": 14, "max_age_days": 90},
	}}
	result.compliant == false
}

test_weak_password_policy if {
	result := ucf_iam_2.result with input as {"normalized_data": {
		"users": [{"username": "alice", "mfa_enabled": true, "access_keys": []}],
		"password_policy": {"min_length": 8, "max_age_days": 90},
	}}
	result.compliant == false
}
