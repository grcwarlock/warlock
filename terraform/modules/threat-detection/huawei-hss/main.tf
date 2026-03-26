###############################################################################
# Huawei Cloud HSS (Host Security Service) Baseline
# Enforces: SI-4 (System Monitoring)
#
# NOTE: HSS has limited Terraform provider support. This module creates a host
# group for organizational purposes. Full HSS feature activation (vulnerability
# scanning, intrusion detection, baseline checks) requires console enablement.
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

# -- SI-4: HSS host group for managed asset organization --------------------

resource "huaweicloud_hss_host_group" "main" {
  name = "${var.name_prefix}-hss-group"
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/huawei-hss"
  resource_id    = huaweicloud_hss_host_group.main.id
  control_ids    = ["SI-4"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    group_name = "${var.name_prefix}-hss-group"
  }
}
