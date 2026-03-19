package iso_27001.a6.a6_02_test

import rego.v1

import data.iso_27001.a6.a6_02

test_compliant_a6_02 if {
	result := a6_02.result with input as {"normalized_data": {
		"policies": {
			"employment_agreements_stored": true,
		},
		"s3": {
			"buckets": [],
		},
		"users": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_02 if {
	result := a6_02.result with input as {"normalized_data": {}}
	result.compliant == false
}
