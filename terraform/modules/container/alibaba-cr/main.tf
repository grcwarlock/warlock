###############################################################################
# Alibaba Cloud Container Registry (CR) Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Settings)
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

# -- SC-28/CM-6: Container Registry Enterprise Edition instance ---------------

resource "alicloud_cr_ee_instance" "main" {
  instance_type  = var.instance_type
  payment_type   = "Subscription"
  period         = 1
  renew_period   = 0
  renewal_status = "ManualRenewal"
  instance_name  = "${var.name_prefix}-cr"
}

# -- CM-6: Namespace for image organization ---------------------------------

resource "alicloud_cr_ee_namespace" "main" {
  instance_id        = alicloud_cr_ee_instance.main.id
  name               = var.name_prefix
  auto_create        = false
  default_visibility = "PRIVATE"
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "container/alibaba-cr"
  resource_id    = alicloud_cr_ee_instance.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    instance_type = var.instance_type
    visibility    = "PRIVATE"
  }
}
