###############################################################################
# Huawei Cloud CTS (Cloud Trace Service) Baseline
# Enforces: AU-2 (Audit Events), AU-6 (Audit Review and Analysis)
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

# -- AU-2: Encrypted OBS bucket for CTS log storage -------------------------

resource "huaweicloud_obs_bucket" "trail" {
  bucket     = var.bucket_name
  acl        = "private"
  encryption = true
  versioning = true

  tags = local.common_tags
}

# -- AU-2/AU-6: CTS tracker with LTS integration ----------------------------

resource "huaweicloud_cts_tracker" "main" {
  bucket_name = huaweicloud_obs_bucket.trail.bucket
  file_prefix = "${var.name_prefix}/cts"
  lts_enabled = true

  depends_on = [huaweicloud_obs_bucket.trail]
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/huawei-cts"
  resource_id    = huaweicloud_cts_tracker.main.id
  control_ids    = ["AU-2", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    lts_enabled = "true"
    bucket_name = huaweicloud_obs_bucket.trail.bucket
  }
}
