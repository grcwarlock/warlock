package nist.ac.ac_2_test

import rego.v1

import data.nist.ac.ac_2

test_all_users_have_mfa if {
	result := ac_2.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "mfa_enabled": true, "access_keys": [], "last_activity": "", "groups": [], "policies": []},
			{"username": "bob", "mfa_enabled": true, "access_keys": [], "last_activity": "", "groups": [], "policies": []},
		],
		"root_account": {"access_keys_present": false, "mfa_enabled": true},
		"total_users": 2,
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_user_without_mfa if {
	result := ac_2.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "mfa_enabled": true, "access_keys": [], "last_activity": "", "groups": [], "policies": []},
			{"username": "bob", "mfa_enabled": false, "access_keys": [], "last_activity": "", "groups": [], "policies": []},
		],
		"root_account": {"access_keys_present": false, "mfa_enabled": true},
		"total_users": 2,
	}}
	result.compliant == false
}

test_root_access_keys if {
	result := ac_2.result with input as {"normalized_data": {
		"users": [],
		"root_account": {"access_keys_present": true, "mfa_enabled": true},
		"total_users": 0,
	}}
	result.compliant == false
}

test_clean_root_no_users if {
	result := ac_2.result with input as {"normalized_data": {
		"users": [],
		"root_account": {"access_keys_present": false, "mfa_enabled": true},
		"total_users": 0,
	}}
	result.compliant == true
}
