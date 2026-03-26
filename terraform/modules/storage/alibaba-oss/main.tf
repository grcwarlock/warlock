###############################################################################
# Alibaba Cloud OSS Baseline
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Enforcement)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    alicloud = { source = "aliyun/alicloud", version = "~> 1.220" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-28/AC-3: OSS bucket with encryption, private ACL, versioning --------

resource "alicloud_oss_bucket" "main" {
  bucket = var.bucket_name

  acl = "private"

  server_side_encryption_rule {
    sse_algorithm     = var.kms_key_id != null ? "KMS" : "AES256"
    kms_master_key_id = var.kms_key_id
  }

  versioning {
    status = "Enabled"
  }

  lifecycle_rule {
    id      = "transition-to-ia"
    enabled = true

    transitions {
      days          = 90
      storage_class = "IA"
    }
  }

  tags = local.common_tags
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/alibaba-oss"
  resource_id    = alicloud_oss_bucket.main.id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    encryption = var.kms_key_id != null ? "KMS" : "AES256"
    versioning = "Enabled"
    acl        = "private"
  }
}
