package nist.pm.pm_8_test

import rego.v1

import data.nist.pm.pm_8

test_compliant_cip if {
	result := pm_8.result with input as {"normalized_data": {"critical_infrastructure_plan": {
		"aligned_with_national_strategy": true,
		"key_resources_identified": true,
		"last_review_days": 100,
		"protection_strategy_defined": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_cip if {
	result := pm_8.result with input as {"normalized_data": {}}
	result.compliant == false
}
