###############################################################################
# Huawei Cloud Account Baseline
# Enforces: AU-2 (Audit Events), AC-6 (Least Privilege), SC-28 (Encryption)
#
# Composite module: CTS tracker + IAM password policy + OBS encryption
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

# -- SC-28: Encrypted OBS bucket for CTS log storage ------------------------

resource "huaweicloud_obs_bucket" "trail" {
  bucket     = var.trail_bucket_name
  acl        = "private"
  encryption = true
  versioning = true

  tags = local.common_tags
}

# -- AU-2: CTS tracker with LTS integration ---------------------------------

resource "huaweicloud_cts_tracker" "main" {
  bucket_name = huaweicloud_obs_bucket.trail.bucket
  file_prefix = "${var.name_prefix}/baseline"
  lts_enabled = true

  depends_on = [huaweicloud_obs_bucket.trail]
}

# -- AC-6: IAM password policy (enterprise baseline) -------------------------

resource "huaweicloud_identity_password_policy" "strict" {
  password_char_combination             = 4
  minimum_password_length               = 14
  number_of_recent_passwords_disallowed = 12
  password_validity_period              = 90
  maximum_consecutive_identical_chars   = 3
  minimum_password_age                  = 0
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "account-baseline/huawei-account"
  resource_id    = huaweicloud_cts_tracker.main.id
  control_ids    = ["AU-2", "AC-6", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    lts_enabled      = "true"
    bucket_encrypted = "true"
    min_password_len = "14"
  }
}
