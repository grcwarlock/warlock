package terraform.s3_test

import rego.v1

import data.terraform.s3

test_s3_public_access_fully_blocked_compliant if {
	count(s3.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_public_access_block",
		"name": "good-block",
		"change": {
			"actions": ["create"],
			"after": {
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
		},
	}]}
}

test_s3_public_access_block_missing_block_acls_noncompliant if {
	count(s3.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket_public_access_block",
		"name": "partial-block",
		"change": {
			"actions": ["create"],
			"after": {
				"block_public_acls": false,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
		},
	}]}
}

test_s3_account_block_compliant if {
	count(s3.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_s3_account_public_access_block",
		"name": "account-block",
		"change": {
			"actions": ["create"],
			"after": {
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			},
		},
	}]}
}

test_s3_account_block_restrict_missing_noncompliant if {
	count(s3.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_s3_account_public_access_block",
		"name": "partial-account-block",
		"change": {
			"actions": ["create"],
			"after": {
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": false,
			},
		},
	}]}
}
