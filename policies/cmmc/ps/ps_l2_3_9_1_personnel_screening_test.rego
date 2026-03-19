package cmmc.ps.ps_l2_3_9_1_test

import rego.v1

import data.cmmc.ps.ps_l2_3_9_1

test_compliant_personnel_screening if {
	result := ps_l2_3_9_1.result with input as {"normalized_data": {"users": [
		{"username": "alice", "cui_access": true, "background_check_completed": true, "screening_age_days": 365, "employment_status": "active", "enabled": true},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_background_check if {
	result := ps_l2_3_9_1.result with input as {"normalized_data": {"users": [
		{"username": "bob", "cui_access": true, "background_check_completed": false, "screening_age_days": 0, "employment_status": "active", "enabled": true},
	]}}
	result.compliant == false
}
