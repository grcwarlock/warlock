package terraform.encryption

import rego.v1

# SC-28 (Protection of Information at Rest): All data stores must have encryption enabled.
# Covers RDS, EBS volumes, ElastiCache, MSK, SQS, SNS, DynamoDB, EFS, ECR.

# ── RDS ──────────────────────────────────────────────────────────────

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_db_instance"
	_is_create_or_update(resource)
	not resource.change.after.storage_encrypted
	msg := sprintf("RDS instance '%s' must have storage_encrypted = true [SC-28]", [resource.name])
}

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_rds_cluster"
	_is_create_or_update(resource)
	not resource.change.after.storage_encrypted
	msg := sprintf("Aurora cluster '%s' must have storage_encrypted = true [SC-28]", [resource.name])
}

# ── EBS ──────────────────────────────────────────────────────────────

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_ebs_volume"
	_is_create_or_update(resource)
	not resource.change.after.encrypted
	msg := sprintf("EBS volume '%s' must be encrypted [SC-28]", [resource.name])
}

# ── ElastiCache ───────────────────────────────────────────────────────

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_elasticache_replication_group"
	_is_create_or_update(resource)
	not resource.change.after.at_rest_encryption_enabled
	msg := sprintf("ElastiCache replication group '%s' must have at_rest_encryption_enabled = true [SC-28]", [resource.name])
}

# ── SQS ──────────────────────────────────────────────────────────────

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_sqs_queue"
	_is_create_or_update(resource)
	not resource.change.after.kms_master_key_id
	resource.change.after.sqs_managed_sse_enabled != true
	msg := sprintf("SQS queue '%s' must have SSE enabled (kms_master_key_id or sqs_managed_sse_enabled) [SC-28]", [resource.name])
}

# ── SNS ──────────────────────────────────────────────────────────────

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_sns_topic"
	_is_create_or_update(resource)
	_no_kms(resource.change.after.kms_master_key_id)
	msg := sprintf("SNS topic '%s' must have kms_master_key_id set for encryption at rest [SC-28]", [resource.name])
}

_no_kms(val) if {
	val == null
}

_no_kms(val) if {
	val == ""
}

_no_kms(val) if {
	not val
}

# ── EFS ──────────────────────────────────────────────────────────────

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_efs_file_system"
	_is_create_or_update(resource)
	not resource.change.after.encrypted
	msg := sprintf("EFS file system '%s' must have encrypted = true [SC-28]", [resource.name])
}

# ── ECR ──────────────────────────────────────────────────────────────

deny contains msg if {
	some resource in input.resource_changes
	resource.type == "aws_ecr_repository"
	_is_create_or_update(resource)
	not resource.change.after.encryption_configuration
	msg := sprintf("ECR repository '%s' must have encryption_configuration set [SC-28]", [resource.name])
}

_is_create_or_update(resource) if {
	resource.change.actions[_] in {"create", "update"}
}
