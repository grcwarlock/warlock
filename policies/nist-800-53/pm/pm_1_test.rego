package nist.pm.pm_1_test

import rego.v1

import data.nist.pm.pm_1

test_compliant_program_plan if {
	result := pm_1.result with input as {"normalized_data": {"security_program_plan": {
		"approved": true,
		"last_review_days": 100,
		"defines_scope": true,
		"defines_roles_responsibilities": true,
		"distributed_to_stakeholders": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_program_plan if {
	result := pm_1.result with input as {"normalized_data": {}}
	result.compliant == false
	count(result.findings) > 0
}

test_noncompliant_plan_outdated if {
	result := pm_1.result with input as {"normalized_data": {"security_program_plan": {
		"approved": true,
		"last_review_days": 400,
		"defines_scope": true,
		"defines_roles_responsibilities": true,
		"distributed_to_stakeholders": true,
	}}}
	result.compliant == false
}
