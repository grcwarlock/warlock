package cmmc.ra.ra_l2_3_11_1_test

import rego.v1

import data.cmmc.ra.ra_l2_3_11_1

test_compliant_risk_assessment if {
	result := ra_l2_3_11_1.result with input as {"normalized_data": {
		"org_units": [
			{"name": "engineering", "risk_assessment_completed": true, "risk_assessment_age_days": 100},
		],
		"systems": [
			{"name": "prod-web", "processes_cui": true, "vulnerability_scanning_enabled": true},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_risk_assessment if {
	result := ra_l2_3_11_1.result with input as {"normalized_data": {
		"org_units": [
			{"name": "engineering", "risk_assessment_completed": false, "risk_assessment_age_days": 0},
		],
		"systems": [
			{"name": "prod-web", "processes_cui": true, "vulnerability_scanning_enabled": true},
		],
	}}
	result.compliant == false
}
