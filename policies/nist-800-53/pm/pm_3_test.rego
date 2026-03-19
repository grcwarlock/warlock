package nist.pm.pm_3_test

import rego.v1

import data.nist.pm.pm_3

test_compliant_resources if {
	result := pm_3.result with input as {"normalized_data": {"security_resource_plan": {
		"discrete_budget_line_item": true,
		"budget_approved": true,
		"staffing_plan_documented": true,
		"last_review_days": 100,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_resource_plan if {
	result := pm_3.result with input as {"normalized_data": {}}
	result.compliant == false
}
