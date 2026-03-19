package iso_27001.a5.a5_03_test

import rego.v1

import data.iso_27001.a5.a5_03

test_compliant_a5_03 if {
	result := a5_03.result with input as {"normalized_data": {
		"iam": {
			"segregated_roles_exist": true,
			"roles": [],
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_03 if {
	result := a5_03.result with input as {"normalized_data": {}}
	result.compliant == false
}
