package nist.pm.pm_7_test

import rego.v1

import data.nist.pm.pm_7

test_compliant_architecture if {
	result := pm_7.result with input as {"normalized_data": {"enterprise_architecture": {
		"security_architecture_integrated": true,
		"last_review_days": 100,
		"includes_reference_models": true,
		"aligned_with_mission": true,
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_architecture if {
	result := pm_7.result with input as {"normalized_data": {}}
	result.compliant == false
}
