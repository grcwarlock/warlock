package iso_27001.a5.a5_11_test

import rego.v1

import data.iso_27001.a5.a5_11

test_compliant_a5_11 if {
	result := a5_11.result with input as {"normalized_data": {
		"policies": {
			"offboarding_process_documented": true,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_11 if {
	result := a5_11.result with input as {"normalized_data": {
		"users": [{
			"username": "terminated-user",
			"status": "terminated",
			"account_enabled": true,
			"mfa_enabled": false,
			"console_access": true,
			"access_keys": [],
		}],
		"policies": {"offboarding_process_documented": false},
	}}
	result.compliant == false
}
