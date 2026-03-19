package hipaa.s164_308.s164_308_a_3_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_3

test_compliant_workforce_security if {
	result := s164_308_a_3.result with input as {"normalized_data": {
		"policies": {
			"workforce_access_authorization": true,
			"termination_procedures": true,
			"background_check_required": true,
		},
		"users": [
			{"username": "alice", "employment_status": "active", "account_enabled": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_terminated_user_active if {
	result := s164_308_a_3.result with input as {"normalized_data": {
		"policies": {
			"workforce_access_authorization": true,
			"termination_procedures": true,
			"background_check_required": true,
		},
		"users": [
			{"username": "bob", "employment_status": "terminated", "account_enabled": true},
		],
	}}
	result.compliant == false
}
