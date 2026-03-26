###############################################################################
# Huawei Cloud OBS Baseline
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Enforcement)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    huaweicloud = { source = "huaweicloud/huaweicloud", version = "~> 1.60" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-28/AC-3: OBS bucket with encryption, private ACL, versioning ---------

resource "huaweicloud_obs_bucket" "main" {
  bucket     = var.bucket_name
  acl        = "private"
  encryption = true
  versioning = true

  lifecycle_rule {
    name    = "transition-to-warm"
    enabled = true

    transition {
      days          = 90
      storage_class = "WARM"
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
  module_name    = "storage/huawei-obs"
  resource_id    = huaweicloud_obs_bucket.main.id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    encryption = "true"
    versioning = "true"
    acl        = "private"
  }
}
