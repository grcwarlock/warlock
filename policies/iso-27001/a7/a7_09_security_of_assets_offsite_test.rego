package iso_27001.a7.a7_09_test

import rego.v1

import data.iso_27001.a7.a7_09

test_compliant_a7_09 if {
	result := a7_09.result with input as {"normalized_data": {
		"ec2": {
			"ebs_encryption_by_default": true,
			"volumes": [],
		},
		"s3": {
			"buckets": [],
		},
		"elb": {
			"listeners": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_09 if {
	result := a7_09.result with input as {"normalized_data": {}}
	result.compliant == false
}
