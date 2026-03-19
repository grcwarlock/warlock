package iso_27001.a5.a5_20_test

import rego.v1

import data.iso_27001.a5.a5_20

test_compliant_a5_20 if {
	result := a5_20.result with input as {"normalized_data": {
		"policies": {
			"supplier_agreements_stored": true,
		},
		"compliance": {
			"baa_accepted": true,
		},
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_20 if {
	result := a5_20.result with input as {"normalized_data": {}}
	result.compliant == false
}
