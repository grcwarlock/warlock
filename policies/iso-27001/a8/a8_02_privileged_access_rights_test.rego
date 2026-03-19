package iso_27001.a8.a8_02_test

import rego.v1

import data.iso_27001.a8.a8_02

test_compliant_a8_02 if {
	result := a8_02.result with input as {"normalized_data": {
		"root_account": {
			"mfa_enabled": true,
		},
		"access_analyzer": {
			"enabled": true,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_02 if {
	result := a8_02.result with input as {"normalized_data": {}}
	result.compliant == false
}
