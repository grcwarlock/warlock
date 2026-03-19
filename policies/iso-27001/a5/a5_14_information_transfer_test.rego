package iso_27001.a5.a5_14_test

import rego.v1

import data.iso_27001.a5.a5_14

test_compliant_a5_14 if {
	result := a5_14.result with input as {"normalized_data": {
		"s3": {
			"buckets": [],
		},
		"elb": {
			"listeners": [],
		},
		"vpcs": [],
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_14 if {
	result := a5_14.result with input as {"normalized_data": {
		"s3": {"buckets": []},
		"elb": {"listeners": []},
		"vpcs": [{"id": "vpc-123", "flow_logs_enabled": false}],
	}}
	result.compliant == false
}
