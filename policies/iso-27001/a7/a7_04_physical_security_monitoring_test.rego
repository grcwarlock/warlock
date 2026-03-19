package iso_27001.a7.a7_04_test

import rego.v1

import data.iso_27001.a7.a7_04

test_compliant_a7_04 if {
	result := a7_04.result with input as {"normalized_data": {
		"guardduty": {
			"enabled": true,
		},
		"security_hub": {
			"enabled": true,
		},
		"cloudwatch": {
			"security_monitoring_dashboard_exists": true,
		},
		"vpcs": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_04 if {
	result := a7_04.result with input as {"normalized_data": {}}
	result.compliant == false
}
