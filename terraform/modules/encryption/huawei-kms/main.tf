###############################################################################
# Huawei Cloud KMS Baseline
# Enforces: SC-12 (Cryptographic Key Management), SC-28 (Encryption at Rest)
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

# -- SC-12/SC-28: KMS key with automatic rotation ----------------------------

resource "huaweicloud_kms_key" "main" {
  key_alias         = "${var.name_prefix}-key"
  key_description   = "${var.name_prefix} Warlock-managed encryption key"
  key_algorithm     = "AES_256"
  rotation_enabled  = true
  rotation_interval = var.rotation_interval
  pending_days      = 7

  tags = local.common_tags
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/huawei-kms"
  resource_id    = huaweicloud_kms_key.main.id
  control_ids    = ["SC-12", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    key_algorithm     = "AES_256"
    rotation_enabled  = "true"
    rotation_interval = tostring(var.rotation_interval)
  }
}
