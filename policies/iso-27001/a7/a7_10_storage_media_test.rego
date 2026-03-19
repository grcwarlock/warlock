package iso_27001.a7.a7_10_test

import rego.v1

import data.iso_27001.a7.a7_10

test_compliant_a7_10 if {
	result := a7_10.result with input as {"normalized_data": {
		"ec2": {
			"ebs_encryption_by_default": true,
			"volumes": [],
		},
		"s3": {
			"buckets": [],
		},
		"kms": {
			"keys": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_10 if {
	result := a7_10.result with input as {"normalized_data": {}}
	result.compliant == false
}
