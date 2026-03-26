###############################################################################
# Netlify Site — Stub Module
# Community Terraform provider only. See remediation.tf for guidance.
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
}

resource "null_resource" "stub" {
  triggers = {
    note = "Stub module. See remediation.tf."
  }
}

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "platform-paas/netlify-site"
  resource_id    = null_resource.stub.id
  control_ids    = []
  remediation_id = var.warlock_remediation_id
  attributes     = {}
}
