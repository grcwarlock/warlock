package nist.at.at_4_test

import rego.v1

import data.nist.at.at_4

test_compliant_training_records if {
	result := at_4.result with input as {"normalized_data": {
		"training_records": {
			"retention_days": 1095,
			"completion_tracking_enabled": true,
			"automated_reporting": true,
			"last_review_days": 30,
		},
		"users": [
			{"username": "alice", "security_training_completed": true, "training_record_documented": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_training_records if {
	result := at_4.result with input as {"normalized_data": {
		"users": [],
	}}
	result.compliant == false
}
