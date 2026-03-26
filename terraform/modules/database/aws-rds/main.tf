###############################################################################
# AWS RDS Hardening
# Enforces: SC-28 (Encryption at Rest), AU-2 (Audit Logging), SC-7 (Network)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-7: DB subnet group ----------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnet-group"
  subnet_ids = var.subnet_ids
  tags       = merge(local.common_tags, { Name = "${var.name_prefix}-db-subnet-group" })
}

# -- SC-7: Security group — ingress from allowed CIDRs only on 5432 -----------

resource "aws_security_group" "db" {
  name        = "${var.name_prefix}-db-sg"
  description = "Security group for ${var.name_prefix} RDS instance"
  vpc_id      = var.vpc_id
  tags        = merge(local.common_tags, { Name = "${var.name_prefix}-db-sg" })
}

resource "aws_security_group_rule" "db_ingress" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidr_blocks
  security_group_id = aws_security_group.db.id
  description       = "SC-7: Allow PostgreSQL from approved CIDRs only"
}

resource "aws_security_group_rule" "db_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
  description       = "Allow all outbound traffic"
}

# -- SC-28/AU-2: RDS instance with encryption, logging, IAM auth --------------

resource "aws_db_instance" "main" {
  identifier = "${var.name_prefix}-db"

  engine         = var.engine
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage = var.allocated_storage
  storage_encrypted = true            # SC-28: mandatory encryption at rest
  kms_key_id        = var.kms_key_arn # SC-28: optional CMEK

  multi_az            = true # SC-28: high availability
  deletion_protection = true # prevent accidental deletion

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]

  backup_retention_period = 7 # AU-2: retain backups for 7 days

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"] # AU-2: audit logging

  iam_database_authentication_enabled = true # AC-3: IAM authentication

  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name_prefix}-db-final-snapshot"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-rds" })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "database/aws-rds"
  resource_id    = aws_db_instance.main.arn
  control_ids    = ["SC-28", "AU-2", "SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    storage_encrypted   = "true"
    multi_az            = "true"
    deletion_protection = "true"
    iam_auth_enabled    = "true"
    backup_retention    = "7"
    cloudwatch_logs     = "postgresql,upgrade"
  }
}
