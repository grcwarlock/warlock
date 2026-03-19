package nist.cp.cp_6_test

import rego.v1

import data.nist.cp.cp_6

test_compliant_alternate_storage if {
	result := cp_6.result with input as {
		"provider": "aws",
		"normalized_data": {
			"alternate_storage": {
				"primary_region": "us-east-1",
				"alternate_region": "us-west-2",
				"agreement_documented": true,
				"encryption_enabled": true,
			},
			"storage_buckets": [
				{"name": "backup-bucket", "contains_backups": true, "cross_region_replication_enabled": true},
			],
		},
	}
	result.compliant == true
	count(result.findings) == 0
}

test_noncompliant_no_alternate_storage if {
	result := cp_6.result with input as {
		"provider": "aws",
		"normalized_data": {"storage_buckets": []},
	}
	result.compliant == false
}
