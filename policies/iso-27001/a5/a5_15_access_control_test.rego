package iso_27001.a5.a5_15_test

import rego.v1

import data.iso_27001.a5.a5_15

test_compliant_a5_15 if {
	result := a5_15.result with input as {"normalized_data": {
		"access_analyzer": {
			"enabled": true,
			"findings": [],
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_15 if {
	result := a5_15.result with input as {"normalized_data": {}}
	result.compliant == false
}
