package hipaa.s164_308.s164_308_a_5_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_5

test_compliant_security_awareness if {
	result := s164_308_a_5.result with input as {"normalized_data": {
		"training": {
			"program_exists": true,
			"phishing_awareness_included": true,
		},
		"users": [
			{"username": "alice", "account_enabled": true, "security_training_completed": true, "training_completion_days": 30},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_user_not_trained if {
	result := s164_308_a_5.result with input as {"normalized_data": {
		"training": {
			"program_exists": true,
			"phishing_awareness_included": true,
		},
		"users": [
			{"username": "bob", "account_enabled": true, "security_training_completed": false, "training_completion_days": 0},
		],
	}}
	result.compliant == false
}
