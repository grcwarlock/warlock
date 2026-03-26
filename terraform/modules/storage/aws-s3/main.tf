###############################################################################
# AWS S3 Bucket Hardening
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
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

# -- SC-28: S3 bucket with encryption at rest ----------------------------------

resource "aws_s3_bucket" "main" {
  bucket = "${var.name_prefix}-${var.bucket_name}"
  tags   = merge(local.common_tags, { Name = "${var.name_prefix}-${var.bucket_name}" })
}

# -- SC-28: Server-side encryption (AES256 default, optional KMS) -------------

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

# -- AC-3: Block all public access --------------------------------------------

resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = true # AC-3: no public ACLs
  block_public_policy     = true # AC-3: no public bucket policies
  ignore_public_acls      = true # AC-3: ignore existing public ACLs
  restrict_public_buckets = true # AC-3: restrict public bucket access
}

# -- SC-28: Versioning --------------------------------------------------------

resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id

  versioning_configuration {
    status = "Enabled"
  }
}

# -- AU-2: Access logging (optional) ------------------------------------------

resource "aws_s3_bucket_logging" "main" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.main.id

  target_bucket = var.log_bucket_id
  target_prefix = "${var.name_prefix}-${var.bucket_name}/"
}

# -- SC-28: Lifecycle — transition to Glacier after 90 days --------------------

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    id     = "glacier-transition"
    status = "Enabled"

    filter {} # apply to all objects

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/aws-s3"
  resource_id    = aws_s3_bucket.main.arn
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    encryption_algorithm = var.kms_key_arn != null ? "aws:kms" : "AES256"
    versioning_enabled   = "true"
    public_access_block  = "true"
    access_logging       = tostring(var.enable_access_logging)
  }
}
