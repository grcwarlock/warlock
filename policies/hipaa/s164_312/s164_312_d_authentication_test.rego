package hipaa.s164_312.s164_312_d_test

import rego.v1

import data.hipaa.s164_312.s164_312_d

test_compliant_authentication if {
	result := s164_312_d.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "ephi_access": true, "mfa_enabled": true, "shared_account": false},
		],
		"config": {"password_policy": {
			"min_length": 14,
			"expiration_enabled": true,
		}},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_weak_password_policy if {
	result := s164_312_d.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "ephi_access": true, "mfa_enabled": true, "shared_account": false},
		],
		"config": {"password_policy": {
			"min_length": 8,
			"expiration_enabled": true,
		}},
	}}
	result.compliant == false
}
