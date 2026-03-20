package terraform.encryption_test

import rego.v1

import data.terraform.encryption

test_rds_encrypted_compliant if {
	count(encryption.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_db_instance",
		"name": "good-rds",
		"change": {
			"actions": ["create"],
			"after": {"storage_encrypted": true},
		},
	}]}
}

test_rds_not_encrypted_noncompliant if {
	count(encryption.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_db_instance",
		"name": "unencrypted-rds",
		"change": {
			"actions": ["create"],
			"after": {"storage_encrypted": false},
		},
	}]}
}

test_ebs_encrypted_compliant if {
	count(encryption.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_ebs_volume",
		"name": "good-ebs",
		"change": {
			"actions": ["create"],
			"after": {"encrypted": true},
		},
	}]}
}

test_ebs_not_encrypted_noncompliant if {
	count(encryption.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_ebs_volume",
		"name": "unencrypted-ebs",
		"change": {
			"actions": ["create"],
			"after": {"encrypted": false},
		},
	}]}
}

test_efs_encrypted_compliant if {
	count(encryption.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_efs_file_system",
		"name": "good-efs",
		"change": {
			"actions": ["create"],
			"after": {"encrypted": true},
		},
	}]}
}

test_efs_not_encrypted_noncompliant if {
	count(encryption.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_efs_file_system",
		"name": "unencrypted-efs",
		"change": {
			"actions": ["create"],
			"after": {"encrypted": false},
		},
	}]}
}

test_sns_with_kms_compliant if {
	count(encryption.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_sns_topic",
		"name": "encrypted-topic",
		"change": {
			"actions": ["create"],
			"after": {"kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc"},
		},
	}]}
}

test_sns_no_kms_noncompliant if {
	count(encryption.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_sns_topic",
		"name": "unencrypted-topic",
		"change": {
			"actions": ["create"],
			"after": {"kms_master_key_id": null},
		},
	}]}
}

test_aurora_encrypted_compliant if {
	count(encryption.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_rds_cluster",
		"name": "good-aurora",
		"change": {
			"actions": ["create"],
			"after": {"storage_encrypted": true},
		},
	}]}
}
