package iso_27001.a7.a7_05_test

import rego.v1

import data.iso_27001.a7.a7_05

test_compliant_a7_05 if {
	result := a7_05.result with input as {"normalized_data": {
		"rds": {
			"instances": [],
		},
		"s3": {
			"buckets": [],
		},
		"ec2": {
			"instances": [],
			"availability_zones": [],
		},
		"backup": {
			"plans": ["item1"],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_05 if {
	result := a7_05.result with input as {"normalized_data": {
		"rds": {"instances": [{"identifier": "db-1", "multi_az": false}]},
		"backup": {"plans": []},
		"s3": {"buckets": []},
		"ec2": {"instances": [], "availability_zones": []},
	}}
	result.compliant == false
}
