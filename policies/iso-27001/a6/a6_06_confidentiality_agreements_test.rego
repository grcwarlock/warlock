package iso_27001.a6.a6_06_test

import rego.v1

import data.iso_27001.a6.a6_06

test_compliant_a6_06 if {
	result := a6_06.result with input as {"normalized_data": {
		"policies": {
			"nda_documents_stored": true,
			"ndas": [],
		},
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a6_06 if {
	result := a6_06.result with input as {"normalized_data": {}}
	result.compliant == false
}
