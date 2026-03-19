package hipaa.s164_308.s164_308_a_7_test

import rego.v1

import data.hipaa.s164_308.s164_308_a_7

test_compliant_contingency_plan if {
	result := s164_308_a_7.result with input as {"normalized_data": {
		"policies": {
			"contingency_plan_exists": true,
			"disaster_recovery_plan": true,
		},
		"config": {
			"backup_enabled": true,
			"backup_tested": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_no_contingency_plan if {
	result := s164_308_a_7.result with input as {"normalized_data": {
		"policies": {
			"contingency_plan_exists": false,
			"disaster_recovery_plan": false,
		},
		"config": {
			"backup_enabled": false,
			"backup_tested": false,
		},
	}}
	result.compliant == false
}
