package nist.at.at_2_test

import rego.v1

import data.nist.at.at_2

test_compliant_all_trained if {
	result := at_2.result with input as {"normalized_data": {
		"security_training": {
			"phishing_module_included": true,
			"social_engineering_module_included": true,
			"insider_threat_module_included": true,
		},
		"users": [
			{"username": "alice", "security_training_completed": true, "training_completion_days": 100, "account_age_days": 365},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_user_not_trained if {
	result := at_2.result with input as {"normalized_data": {
		"security_training": {
			"phishing_module_included": true,
			"social_engineering_module_included": true,
			"insider_threat_module_included": true,
		},
		"users": [
			{"username": "bob", "security_training_completed": false, "account_age_days": 365},
		],
	}}
	result.compliant == false
}
