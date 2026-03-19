package hipaa.s164_312.s164_312_a_1_test

import rego.v1

import data.hipaa.s164_312.s164_312_a_1

test_compliant_access_control if {
	result := s164_312_a_1.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "unique_id": true, "ephi_access": true, "mfa_enabled": true},
		],
		"config": {"session_timeout_enabled": true},
		"policies": {"emergency_access_procedure": true},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_user_without_mfa if {
	result := s164_312_a_1.result with input as {"normalized_data": {
		"users": [
			{"username": "bob", "unique_id": true, "ephi_access": true, "mfa_enabled": false},
		],
		"config": {"session_timeout_enabled": true},
		"policies": {"emergency_access_procedure": true},
	}}
	result.compliant == false
}
