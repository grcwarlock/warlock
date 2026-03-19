###############################################################################
# AWS Secure Account Baseline
# Enforces: AU-2 (CloudTrail), AU-6 (GuardDuty/Security Hub),
#           SC-28 (Encryption), AC-6 (IAM password policy)
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# ── AU-2: CloudTrail (Event Logging) ─────────────────────────────────

resource "aws_s3_bucket" "audit_logs" {
  bucket        = var.log_bucket_name
  force_destroy = false
  tags          = local.common_tags
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.audit_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/AWSLogs/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # NIST AU-2
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = local.common_tags
}

# ── AU-6: GuardDuty (Threat Detection) ───────────────────────────────

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
  tags   = local.common_tags
}

# ── AU-6: Security Hub (Centralized Findings) ────────────────────────

resource "aws_securityhub_account" "main" {
  count                        = var.enable_security_hub ? 1 : 0
  enable_default_standards     = true
  auto_enable_controls         = true
  control_finding_generator    = "SECURITY_CONTROL"
}

# ── AC-6: IAM Password Policy ────────────────────────────────────────

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# ── SC-28: EBS Default Encryption ────────────────────────────────────

resource "aws_ebs_encryption_by_default" "enabled" {
  enabled = true
}

# ── AC-3: Block Public S3 Access ─────────────────────────────────────

resource "aws_s3_account_public_access_block" "block" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
