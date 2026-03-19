package nist.ia.ia_2_test

import rego.v1

import data.nist.ia.ia_2

test_compliant_identification if {
	result := ia_2.result with input as {"normalized_data": {
		"users": [
			{"username": "alice.smith", "mfa_enabled": true, "policies": [{"effect": "Allow", "action": "*"}]},
		],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_mfa_privileged if {
	result := ia_2.result with input as {"normalized_data": {
		"users": [
			{"username": "bob.jones", "mfa_enabled": false, "policies": [{"effect": "Allow", "action": "*"}]},
		],
	}}
	result.compliant == false
}
