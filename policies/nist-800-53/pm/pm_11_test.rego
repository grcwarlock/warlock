package nist.pm.pm_11_test

import rego.v1

import data.nist.pm.pm_11

test_compliant_mission_processes if {
	result := pm_11.result with input as {"normalized_data": {"mission_business_processes": {
		"last_review_days": 100,
		"processes": [{"name": "proc1", "protection_needs_determined": true, "risk_determination_completed": true}],
	}}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_processes if {
	result := pm_11.result with input as {"normalized_data": {}}
	result.compliant == false
}
