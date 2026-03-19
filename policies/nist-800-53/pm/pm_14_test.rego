package nist.pm.pm_14_test

import rego.v1

import data.nist.pm.pm_14

test_compliant_ttm if {
	result := pm_14.result with input as {"normalized_data": {
		"testing_training_monitoring": {
			"security_testing_conducted": true,
			"last_test_days": 100,
			"training_program_established": true,
			"monitoring_strategy_defined": true,
			"remediation_tracking": true,
		},
		"system_inventory": {"systems": [{"name": "sys1", "security_testing_completed": true}]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_ttm if {
	result := pm_14.result with input as {"normalized_data": {}}
	result.compliant == false
}
