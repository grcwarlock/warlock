package iso_27001.a8.a8_11_test

import rego.v1

import data.iso_27001.a8.a8_11

test_compliant_a8_11 if {
	result := a8_11.result with input as {"normalized_data": {
		"macie": {
			"enabled": true,
			"high_severity_finding_count": 0,
			"classification_jobs": ["item1"],
		},
		"cloudwatch": {
			"data_protection_policies_configured": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_11 if {
	result := a8_11.result with input as {"normalized_data": {}}
	result.compliant == false
}
