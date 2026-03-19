package iso_27001.a8.a8_10_test

import rego.v1

import data.iso_27001.a8.a8_10

test_compliant_a8_10 if {
	result := a8_10.result with input as {"normalized_data": {
		"s3": {
			"buckets": [],
		},
		"cloudwatch": {
			"log_groups": [],
		},
		"dynamodb": {
			"tables": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a8_10 if {
	result := a8_10.result with input as {"normalized_data": {
		"s3": {"buckets": [{"name": "test-bucket", "lifecycle_policy_configured": false}]},
		"cloudwatch": {"log_groups": [{"name": "/aws/test", "retention_in_days": null}]},
		"dynamodb": {"tables": []},
	}}
	result.compliant == false
}
