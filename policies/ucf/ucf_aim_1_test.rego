package ucf.aim.ucf_aim_1_test

import rego.v1

import data.ucf.aim.ucf_aim_1

test_ai_policy_exists if {
	result := ucf_aim_1.result with input as {"normalized_data": {
		"policies": {"ai_governance_policy": {"exists": true, "approved": true}},
	}}
	result.compliant == true
}

test_no_ai_policy if {
	result := ucf_aim_1.result with input as {"normalized_data": {"policies": {}}}
	result.compliant == false
}

test_ai_policy_not_approved if {
	result := ucf_aim_1.result with input as {"normalized_data": {
		"policies": {"ai_governance_policy": {"exists": true, "approved": false}},
	}}
	result.compliant == false
}
