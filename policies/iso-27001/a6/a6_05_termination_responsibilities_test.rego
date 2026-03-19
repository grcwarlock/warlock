package iso_27001.a6.a6_05_test

import rego.v1

import data.iso_27001.a6.a6_05

test_compliant_a6_05 if {
	result := a6_05.result with input as {"normalized_data": {
		"policies": {
			"offboarding_procedure_documented": true,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_05 if {
	result := a6_05.result with input as {"normalized_data": {
		"users": [{
			"username": "terminated-user",
			"tags": {"Status": "Terminated"},
			"access_keys": [{"id": "AKIA123", "status": "Active"}],
			"console_access": true,
			"groups": ["Admins"],
		}],
		"policies": {"offboarding_procedure_documented": false},
	}}
	result.compliant == false
}
