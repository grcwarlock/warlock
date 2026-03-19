package iso_27001.a5.a5_27_test

import rego.v1

import data.iso_27001.a5.a5_27

test_compliant_a5_27 if {
	result := a5_27.result with input as {"normalized_data": {
		"security_hub": {
			"incident_trend_insights_exist": true,
		},
		"cloudwatch": {
			"security_dashboard_exists": true,
		},
		"policies": {
			"post_incident_reports_stored": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_27 if {
	result := a5_27.result with input as {"normalized_data": {}}
	result.compliant == false
}
