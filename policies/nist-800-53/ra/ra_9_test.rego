package nist.ra.ra_9_test

import rego.v1

import data.nist.ra.ra_9

test_compliant_criticality if {
	result := ra_9.result with input as {"normalized_data": {
		"criticality_analysis": {
			"last_review_days": 100,
			"mission_mapping_completed": true,
			"dependencies_identified": true,
		},
		"system_inventory": {"systems": [{"name": "sys1", "criticality_level": "high"}]},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_analysis if {
	result := ra_9.result with input as {"normalized_data": {}}
	result.compliant == false
}
