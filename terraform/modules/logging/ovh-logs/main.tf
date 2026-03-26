###############################################################################
# OVH Logs Data Platform — STUB
# Enforces: AU-2 (Audit Logging)
#
# OVH Logs Data Platform has limited Terraform support. This module is a stub
# placeholder. See remediation.tf for details and manual configuration steps.
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
}

resource "null_resource" "stub" {
  triggers = {
    note = "This is a stub module. See remediation.tf for provider limitations."
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/ovh-logs"
  resource_id    = "stub-ovh-logs"
  control_ids    = ["AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    stub = "true"
  }
}
