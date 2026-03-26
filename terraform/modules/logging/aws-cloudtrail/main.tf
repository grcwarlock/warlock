###############################################################################
# AWS CloudTrail Organization Trail
# Enforces: AU-2 (Event Logging), AU-9 (Log Integrity), AU-12 (Audit Generation)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
  effective_kms_key_arn = var.kms_key_arn
}

# -- AU-2: Central S3 bucket for org trail ------------------------------------

resource "aws_s3_bucket" "org_trail" {
  bucket        = var.trail_bucket_name
  force_destroy = false
  tags          = local.common_tags
}

resource "aws_s3_bucket_versioning" "org_trail" {
  bucket = aws_s3_bucket.org_trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "org_trail" {
  bucket = aws_s3_bucket.org_trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null ? true : false
  }
}

resource "aws_s3_bucket_public_access_block" "org_trail" {
  bucket                  = aws_s3_bucket.org_trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "org_trail" {
  bucket = aws_s3_bucket.org_trail.id

  rule {
    id     = "org-trail-lifecycle"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.log_retention_days
    }

    expiration {
      expired_object_delete_marker = true
    }
  }
}

# S3 bucket policy allowing org-wide CloudTrail writes
resource "aws_s3_bucket_policy" "org_trail" {
  bucket = aws_s3_bucket.org_trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.org_trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.org_trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "AWSCloudTrailOrgWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.org_trail.arn}/AWSLogs/${var.organization_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

# -- AU-2/AU-9: CloudWatch Logs for near-real-time analysis --------------------

resource "aws_cloudwatch_log_group" "org_trail" {
  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.effective_kms_key_arn
  tags              = local.common_tags
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.trail_name}-cloudwatch-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "cloudtrail-to-cloudwatch"
  role = aws_iam_role.cloudtrail_cloudwatch.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.org_trail.arn}:*"
    }]
  })
}

# -- AU-12: Organization-wide trail with data events --------------------------

resource "aws_cloudtrail" "org" {
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.org_trail.id
  is_multi_region_trail         = true # AU-2: capture all regions
  is_organization_trail         = true # org-wide coverage
  include_global_service_events = true
  enable_log_file_validation    = true # AU-9: log integrity
  enable_logging                = true
  kms_key_id                    = local.effective_kms_key_arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.org_trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  # Management events -- all read/write
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  # Data events for S3 (AU-12)
  dynamic "event_selector" {
    for_each = var.enable_s3_data_events ? [1] : []
    content {
      read_write_type = "All"
      data_resource {
        type   = "AWS::S3::Object"
        values = ["arn:aws:s3:::"]
      }
    }
  }

  # Data events for Lambda (AU-12)
  dynamic "event_selector" {
    for_each = var.enable_lambda_data_events ? [1] : []
    content {
      read_write_type = "All"
      data_resource {
        type   = "AWS::Lambda::Function"
        values = ["arn:aws:lambda"]
      }
    }
  }

  tags = local.common_tags

  depends_on = [
    aws_s3_bucket_policy.org_trail,
    aws_cloudwatch_log_group.org_trail,
  ]
}

# -- SNS for CloudTrail alerts ------------------------------------------------

resource "aws_sns_topic" "cloudtrail_alerts" {
  count = var.create_sns_topic ? 1 : 0
  name  = "${var.trail_name}-alerts"
  tags  = local.common_tags
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/aws-cloudtrail"
  resource_id    = aws_cloudtrail.org.arn
  control_ids    = ["AU-2", "AU-9", "AU-12"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    is_multi_region       = "true"
    is_organization_trail = "true"
    log_file_validation   = "true"
    s3_data_events        = tostring(var.enable_s3_data_events)
    lambda_data_events    = tostring(var.enable_lambda_data_events)
    log_retention_days    = tostring(var.log_retention_days)
  }
}
