package iso_27001.a5.a5_34_test

import rego.v1

import data.iso_27001.a5.a5_34

test_compliant_a5_34 if {
	result := a5_34.result with input as {"normalized_data": {
		"macie": {
			"enabled": true,
			"pii_discovery_jobs_running": true,
		},
		"policies": {
			"privacy_policy_documented": true,
		},
		"s3": {
			"buckets": [],
		},
	}}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_a5_34 if {
	result := a5_34.result with input as {"normalized_data": {}}
	result.compliant == false
}
