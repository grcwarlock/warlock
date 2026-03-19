package cmmc.at.at_l2_3_2_2_test

import rego.v1

import data.cmmc.at.at_l2_3_2_2

test_compliant_insider_threat if {
	result := at_l2_3_2_2.result with input as {"normalized_data": {
		"users": [
			{"username": "alice", "enabled": true, "insider_threat_training_completed": true, "insider_threat_training_age_days": 30},
		],
		"org_units": [
			{"name": "engineering", "insider_threat_reporting_mechanism": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_insider_threat_training if {
	result := at_l2_3_2_2.result with input as {"normalized_data": {
		"users": [
			{"username": "bob", "enabled": true, "insider_threat_training_completed": false, "insider_threat_training_age_days": 0},
		],
		"org_units": [
			{"name": "engineering", "insider_threat_reporting_mechanism": true},
		],
	}}
	result.compliant == false
}
