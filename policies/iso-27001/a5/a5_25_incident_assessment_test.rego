package iso_27001.a5.a5_25_test

import rego.v1

import data.iso_27001.a5.a5_25

test_compliant_a5_25 if {
	result := a5_25.result with input as {"normalized_data": {
		"security_hub": {
			"finding_aggregation_enabled": true,
			"triage_insights_configured": true,
			"new_findings_count": 50,
			"custom_actions": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_25 if {
	result := a5_25.result with input as {"normalized_data": {
		"security_hub": {
			"enabled": true,
			"finding_aggregation_enabled": false,
			"new_findings_count": 200,
			"triage_insights_configured": false,
			"custom_actions": [],
		},
	}}
	result.compliant == false
}
