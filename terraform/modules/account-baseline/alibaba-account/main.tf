###############################################################################
# Alibaba Cloud Account Baseline
# Enforces: AU-2 (Audit Events), AC-6 (Least Privilege), SC-28 (Encryption)
#
# Composite module: ActionTrail + RAM password policy + OSS encryption
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

# -- SC-28: Encrypted OSS bucket for ActionTrail logs -----------------------

resource "alicloud_oss_bucket" "trail" {
  bucket = var.trail_bucket_name

  acl = "private"

  server_side_encryption_rule {
    sse_algorithm = "AES256"
  }

  versioning {
    status = "Enabled"
  }

  tags = local.common_tags
}

# -- AU-2: ActionTrail trail with full event logging -------------------------

resource "alicloud_actiontrail_trail" "main" {
  trail_name      = "${var.name_prefix}-baseline-trail"
  oss_bucket_name = alicloud_oss_bucket.trail.id
  event_rw        = "All"

  depends_on = [alicloud_oss_bucket.trail]
}

# -- AC-6: RAM account password policy (enterprise baseline) -----------------

resource "alicloud_ram_account_password_policy" "strict" {
  minimum_password_length      = 14
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
  max_password_age             = 90
  password_reuse_prevention    = 12
  max_login_attempts           = 5
  hard_expiry                  = false
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "account-baseline/alibaba-account"
  resource_id    = alicloud_actiontrail_trail.main.id
  control_ids    = ["AU-2", "AC-6", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    trail_event_rw   = "All"
    bucket_encrypted = "AES256"
    min_password_len = "14"
  }
}
