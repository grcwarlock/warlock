package cmmc.ir.ir_l2_3_6_1_test

import rego.v1

import data.cmmc.ir.ir_l2_3_6_1

test_compliant_incident_handling if {
	result := ir_l2_3_6_1.result with input as {"normalized_data": {"org_units": [
		{"name": "engineering", "incident_response_plan_documented": true, "incident_response_team_assigned": true, "ir_plan_last_tested_days": 90},
	]}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_incident_plan if {
	result := ir_l2_3_6_1.result with input as {"normalized_data": {"org_units": [
		{"name": "engineering", "incident_response_plan_documented": false, "incident_response_team_assigned": false, "ir_plan_last_tested_days": 0},
	]}}
	result.compliant == false
}
