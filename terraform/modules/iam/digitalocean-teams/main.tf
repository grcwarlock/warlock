###############################################################################
# DigitalOcean Teams — Documentation-Only Stub
# Enforces: AC-2 (Account Management)
#
# DigitalOcean team management is not available via the Terraform provider.
# Teams must be configured through the DigitalOcean dashboard.
# This module exists to document that limitation and register evidence.
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
}

resource "null_resource" "teams_documentation" {
  triggers = {
    note = "DigitalOcean team management is not available via Terraform. Use the dashboard."
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/digitalocean-teams"
  resource_id    = "digitalocean-teams-manual"
  control_ids    = ["AC-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    management_method = "dashboard-only"
    terraform_support = "false"
  }
}
