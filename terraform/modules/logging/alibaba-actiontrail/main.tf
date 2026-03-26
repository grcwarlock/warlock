###############################################################################
# Alibaba Cloud ActionTrail Baseline
# Enforces: AU-2 (Audit Events), AU-6 (Audit Review and Analysis)
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

# -- AU-2: OSS bucket for trail storage (encrypted) --------------------------

resource "alicloud_oss_bucket" "trail" {
  bucket = var.trail_bucket_name

  server_side_encryption_rule {
    sse_algorithm = "AES256"
  }

  acl = "private"

  versioning {
    status = "Enabled"
  }

  tags = local.common_tags
}

# -- AU-2/AU-6: ActionTrail trail with full read/write logging ---------------

resource "alicloud_actiontrail_trail" "main" {
  trail_name            = "${var.name_prefix}-actiontrail"
  oss_bucket_name       = alicloud_oss_bucket.trail.id
  event_rw              = "All"
  is_organization_trail = false

  depends_on = [alicloud_oss_bucket.trail]
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/alibaba-actiontrail"
  resource_id    = alicloud_actiontrail_trail.main.id
  control_ids    = ["AU-2", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    event_rw    = "All"
    bucket_name = alicloud_oss_bucket.trail.id
  }
}
