package iso_27001.a7.a7_14_test

import rego.v1

import data.iso_27001.a7.a7_14

test_compliant_a7_14 if {
	result := a7_14.result with input as {"normalized_data": {
		"ec2": {
			"volumes": [],
			"snapshots": [],
		},
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a7_14 if {
	result := a7_14.result with input as {"normalized_data": {
		"ec2": {
			"volumes": [{"id": "vol-123", "state": "available", "encrypted": false}],
			"snapshots": [{"id": "snap-123", "age_days": 400}],
		},
		"s3": {"buckets": []},
	}}
	result.compliant == false
}
