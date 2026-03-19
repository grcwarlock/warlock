package cmmc.ac.ac_l2_3_1_1_test

import rego.v1

import data.cmmc.ac.ac_l2_3_1_1

test_compliant_authorized_access if {
	result := ac_l2_3_1_1.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "mfa_enabled": true, "last_login_days": 5, "enabled": true},
		],
		"systems": [
			{"name": "prod-web", "session_timeout_configured": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_inactive_user if {
	result := ac_l2_3_1_1.result with input as {"normalized_data": {
		"users": [
			{"username": "bob", "mfa_enabled": true, "last_login_days": 120, "enabled": true},
		],
		"systems": [
			{"name": "prod-web", "session_timeout_configured": true},
		],
	}}
	result.compliant == false
}
