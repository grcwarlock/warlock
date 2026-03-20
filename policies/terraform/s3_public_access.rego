package terraform.s3

import rego.v1

# AC-3: S3 bucket public access block must be fully configured.
# Checks both the bucket-level and account-level public access block resources.

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	_is_create_or_update(resource)
	not resource.change.after.block_public_acls
	msg := sprintf("S3 public access block '%s' must set block_public_acls = true [AC-3]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	_is_create_or_update(resource)
	not resource.change.after.block_public_policy
	msg := sprintf("S3 public access block '%s' must set block_public_policy = true [AC-3]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	_is_create_or_update(resource)
	not resource.change.after.ignore_public_acls
	msg := sprintf("S3 public access block '%s' must set ignore_public_acls = true [AC-3]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_bucket_public_access_block"
	_is_create_or_update(resource)
	not resource.change.after.restrict_public_buckets
	msg := sprintf("S3 public access block '%s' must set restrict_public_buckets = true [AC-3]", [resource.name])
}

# Account-level public access block
deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_account_public_access_block"
	_is_create_or_update(resource)
	not resource.change.after.block_public_acls
	msg := sprintf("S3 account public access block '%s' must set block_public_acls = true [AC-3]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_s3_account_public_access_block"
	_is_create_or_update(resource)
	not resource.change.after.restrict_public_buckets
	msg := sprintf("S3 account public access block '%s' must set restrict_public_buckets = true [AC-3]", [resource.name])
}

_is_create_or_update(resource) if {
	resource.change.actions[_] in {"create", "update"}
}
