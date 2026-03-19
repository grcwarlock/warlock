package iso_27001.a8.a8_30_test

import rego.v1

import data.iso_27001.a8.a8_30

test_compliant_a8_30 if {
	result := a8_30.result with input as {"normalized_data": {
		"cloudtrail": {
			"enabled": true,
		},
		"iam": {
			"roles": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_30 if {
	result := a8_30.result with input as {"normalized_data": {}}
	result.compliant == false
}
