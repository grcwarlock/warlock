package nist.ir.ir_5_test

import rego.v1

import data.nist.ir.ir_5

test_compliant_incident_monitoring if {
	result := ir_5.result with input as {"normalized_data": {
		"incident_monitoring": {
			"ticketing_system_configured": true,
			"severity_classification_defined": true,
			"untracked_incidents": 0,
			"trend_analysis_enabled": true,
			"automated_alerting": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_monitoring if {
	result := ir_5.result with input as {"normalized_data": {}}
	result.compliant == false
}
