###############################################################################
# Alibaba Cloud Security Center Baseline
# Enforces: SI-4 (System Monitoring), AU-6 (Audit Review and Analysis)
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

# -- SI-4: Service-linked role for Security Center ---------------------------

resource "alicloud_security_center_service_linked_role" "main" {
}

# -- SI-4/AU-6: Security Center group for asset organization ----------------

resource "alicloud_security_center_group" "main" {
  group_name = "${var.name_prefix}-security-group"
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/alibaba-security-center"
  resource_id    = alicloud_security_center_group.main.id
  control_ids    = ["SI-4", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    group_name = "${var.name_prefix}-security-group"
  }
}
