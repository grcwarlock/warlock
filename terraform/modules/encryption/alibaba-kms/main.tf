###############################################################################
# Alibaba Cloud KMS Baseline
# Enforces: SC-12 (Cryptographic Key Management), SC-28 (Encryption at Rest)
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

# -- SC-12: KMS Key with automatic rotation and HSM protection ---------------

resource "alicloud_kms_key" "main" {
  description            = "${var.name_prefix} Warlock-managed encryption key"
  automatic_rotation     = "Enabled"
  rotation_interval      = var.rotation_period
  protection_level       = "HSM"
  key_usage              = "ENCRYPT/DECRYPT"
  pending_window_in_days = 7

  tags = local.common_tags
}

# -- SC-12: Key alias for human-readable reference ----------------------------

resource "alicloud_kms_alias" "main" {
  alias_name = "alias/${var.name_prefix}-key"
  key_id     = alicloud_kms_key.main.id
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/alibaba-kms"
  resource_id    = alicloud_kms_key.main.id
  control_ids    = ["SC-12", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    rotation_period  = var.rotation_period
    protection_level = "HSM"
  }
}
