package iso_27001.a6.a6_07_test

import rego.v1

import data.iso_27001.a6.a6_07

test_compliant_a6_07 if {
	result := a6_07.result with input as {"normalized_data": {
		"vpn": {
			"client_vpn_configured": true,
			"connection_logging_enabled": true,
			"mutual_authentication_enabled": true,
		},
		"policies": {
			"remote_working_policy_documented": true,
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_07 if {
	result := a6_07.result with input as {"normalized_data": {}}
	result.compliant == false
}
