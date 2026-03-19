package iso_27001.a8.a8_05_test

import rego.v1

import data.iso_27001.a8.a8_05

test_compliant_a8_05 if {
	result := a8_05.result with input as {"normalized_data": {
		"root_account": {
			"mfa_enabled": true,
		},
		"users": [],
		"iam": {
			"saml_providers": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_05 if {
	result := a8_05.result with input as {"normalized_data": {}}
	result.compliant == false
}
