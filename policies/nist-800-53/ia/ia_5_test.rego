package nist.ia.ia_5_test

import rego.v1

import data.nist.ia.ia_5

test_compliant_authenticator_mgmt if {
	result := ia_5.result with input as {"normalized_data": {
		"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_symbols": true,
		},
		"users": [
			{"username": "alice", "access_keys": [{"status": "Active", "last_used_days": 30}], "last_activity": "2025-01-01", "last_activity_days": 10},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_weak_password if {
	result := ia_5.result with input as {"normalized_data": {
		"password_policy": {
			"minimum_password_length": 8,
			"require_uppercase_characters": true,
			"require_symbols": true,
		},
		"users": [],
	}}
	result.compliant == false
}
