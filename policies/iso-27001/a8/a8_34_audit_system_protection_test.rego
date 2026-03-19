package iso_27001.a8.a8_34_test

import rego.v1

import data.iso_27001.a8.a8_34

test_compliant_a8_34 if {
	result := a8_34.result with input as {"normalized_data": {
		"iam": {
			"auditor_role_exists": true,
			"roles": [],
		},
		"cloudtrail": {
			"enabled": true,
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_34 if {
	result := a8_34.result with input as {"normalized_data": {}}
	result.compliant == false
}
