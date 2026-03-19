package iso_27001.a5.a5_17_test

import rego.v1

import data.iso_27001.a5.a5_17

test_compliant_a5_17 if {
	result := a5_17.result with input as {"normalized_data": {
		"root_account": {
			"mfa_enabled": true,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_17 if {
	result := a5_17.result with input as {"normalized_data": {}}
	result.compliant == false
}
