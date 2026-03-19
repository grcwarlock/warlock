package nist.pm.pm_10_test

import rego.v1

import data.nist.pm.pm_10

test_compliant_auth_process if {
	result := pm_10.result with input as {"normalized_data": {
		"authorization_process": {
			"continuous_monitoring_integrated": true,
			"common_controls_identified": true,
		},
		"system_inventory": {"systems": [{"name": "sys1", "authorizing_official": "ao1", "ato_expiration_days": 365}]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_auth_process if {
	result := pm_10.result with input as {"normalized_data": {}}
	result.compliant == false
}
