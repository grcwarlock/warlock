package hipaa.s164_308.s164_308_a_4_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_4

test_compliant_access_management if {
	result := s164_308_a_4.result with input as {"normalized_data": {
		"config": {"role_based_access_enabled": true},
		"users": [
			{"username": "alice", "admin_access": false, "admin_justified": false},
		],
		"policies": {
			"periodic_access_review": true,
			"last_access_review_days": 30,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_overprivileged_user if {
	result := s164_308_a_4.result with input as {"normalized_data": {
		"config": {"role_based_access_enabled": true},
		"users": [
			{"username": "bob", "admin_access": true, "admin_justified": false},
		],
		"policies": {
			"periodic_access_review": true,
			"last_access_review_days": 30,
		},
	}}
	result.compliant == false
}
