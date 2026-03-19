package nist.pm.pm_9_test

import rego.v1

import data.nist.pm.pm_9

test_compliant_risk_strategy if {
	result := pm_9.result with input as {"normalized_data": {"risk_management_strategy": {
		"risk_tolerance_defined": true,
		"approved_by_leadership": true,
		"last_review_days": 100,
		"risk_framework_adopted": true,
		"risk_communication_plan": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_strategy if {
	result := pm_9.result with input as {"normalized_data": {}}
	result.compliant == false
}
