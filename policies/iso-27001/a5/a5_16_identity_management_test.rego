package iso_27001.a5.a5_16_test

import rego.v1

import data.iso_27001.a5.a5_16

test_compliant_a5_16 if {
	result := a5_16.result with input as {"normalized_data": {
		"sso": {
			"enabled": true,
		},
		"iam": {
			"credential_report_generated": true,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_16 if {
	result := a5_16.result with input as {"normalized_data": {}}
	result.compliant == false
}
