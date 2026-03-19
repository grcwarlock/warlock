package cmmc.ac.ac_l2_3_1_5_test

import rego.v1

import data.cmmc.ac.ac_l2_3_1_5

test_compliant_least_privilege if {
	result := ac_l2_3_1_5.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "admin_access": true, "admin_justified": true, "privileged": true, "last_privilege_review_days": 30, "shared_account": false},
		],
		"root_account": {"last_login_days": 90},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_excessive_admin if {
	result := ac_l2_3_1_5.result with input as {"normalized_data": {
		"users": [
			{"username": "bob", "admin_access": true, "admin_justified": false, "privileged": true, "last_privilege_review_days": 30, "shared_account": false},
		],
		"root_account": {"last_login_days": 90},
	}}
	result.compliant == false
}
