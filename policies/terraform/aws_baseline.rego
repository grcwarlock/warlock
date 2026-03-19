package terraform.aws

import rego.v1

# Terraform plan-time compliance for AWS resources
# Use with conftest: conftest test tfplan.json -p policies/terraform/

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket"
	not has_encryption(resource)
	msg := sprintf("S3 bucket '%s' must have server-side encryption enabled [SC-28]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_security_group_rule"
	resource.change.after.type == "ingress"
	resource.change.after.from_port <= 22
	resource.change.after.to_port >= 22
	resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
	msg := sprintf("Security group '%s' allows SSH from 0.0.0.0/0 [SC-7]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_security_group_rule"
	resource.change.after.type == "ingress"
	resource.change.after.from_port <= 3389
	resource.change.after.to_port >= 3389
	resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
	msg := sprintf("Security group '%s' allows RDP from 0.0.0.0/0 [SC-7]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_db_instance"
	not resource.change.after.storage_encrypted
	msg := sprintf("RDS instance '%s' must have encryption enabled [SC-28]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_instance"
	resource.change.after.metadata_options[0].http_tokens != "required"
	msg := sprintf("EC2 '%s' must require IMDSv2 [CM-6]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_cloudtrail"
	not resource.change.after.enable_log_file_validation
	msg := sprintf("CloudTrail '%s' must have log validation [AU-2]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_ebs_volume"
	not resource.change.after.encrypted
	msg := sprintf("EBS volume '%s' must be encrypted [SC-28]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	not resource.change.after.block_public_acls
	msg := sprintf("S3 bucket '%s' must block public ACLs [AC-3]", [resource.name])
}

has_encryption(resource) if {
	resource.change.after.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].sse_algorithm
}
