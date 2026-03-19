package cmmc.ca.ca_l2_3_12_1_test

import rego.v1

import data.cmmc.ca.ca_l2_3_12_1

test_compliant_security_assessment if {
	result := ca_l2_3_12_1.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "security_assessment_completed": true, "assessment_age_days": 100},
		],
		"poams": [
			{"id": "POAM-001", "status": "closed", "overdue": false},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_overdue_poam if {
	result := ca_l2_3_12_1.result with input as {"normalized_data": {
		"systems": [
			{"name": "prod-web", "security_assessment_completed": true, "assessment_age_days": 100},
		],
		"poams": [
			{"id": "POAM-001", "status": "open", "overdue": true},
		],
	}}
	result.compliant == false
}
