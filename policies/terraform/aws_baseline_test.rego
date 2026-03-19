package terraform.aws_test

import rego.v1

import data.terraform.aws

test_compliant_s3_encrypted if {
	count(aws.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket",
		"name": "good-bucket",
		"change": {"after": {"server_side_encryption_configuration": [{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}]}},
	}]}
}

test_noncompliant_s3_no_encryption if {
	count(aws.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_s3_bucket",
		"name": "bad-bucket",
		"change": {"after": {}},
	}]}
}

test_noncompliant_sg_ssh_open if {
	count(aws.deny) > 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "bad-sg",
		"change": {"after": {"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}},
	}]}
}

test_compliant_sg_restricted if {
	count(aws.deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"name": "good-sg",
		"change": {"after": {"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}},
	}]}
}
