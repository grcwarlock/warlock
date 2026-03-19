package iso_27001.a5.a5_19_test

import rego.v1

import data.iso_27001.a5.a5_19

test_compliant_a5_19 if {
	result := a5_19.result with input as {"normalized_data": {
		"cloudtrail": {
			"enabled": true,
		},
		"policies": {
			"supplier_security_policy": true,
		},
		"iam": {
			"roles": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_19 if {
	result := a5_19.result with input as {"normalized_data": {}}
	result.compliant == false
}
