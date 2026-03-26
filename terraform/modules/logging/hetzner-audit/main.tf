###############################################################################
# Hetzner Audit Logging — STUB
# Enforces: AU-2 (Audit Logging)
#
# Hetzner Cloud does not provide native audit logging via API or Terraform.
# See remediation.tf for manual configuration guidance.
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
  module_name    = "logging/hetzner-audit"
  resource_id    = "stub-hetzner-audit"
  control_ids    = ["AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    stub = "true"
  }
}
