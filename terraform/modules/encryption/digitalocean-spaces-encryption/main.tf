###############################################################################
# DigitalOcean Spaces Encryption — Documentation-Only Stub
# Enforces: SC-28 (Encryption at Rest)
#
# DigitalOcean Spaces encrypts all data at rest by default using AES-256.
# There is no user-managed key option. This module exists to document that
# posture and register evidence with Warlock.
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
}

resource "null_resource" "spaces_encryption_documentation" {
  triggers = {
    note = "DigitalOcean Spaces encrypts at rest by default (AES-256). No user-managed keys."
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/digitalocean-spaces-encryption"
  resource_id    = "digitalocean-spaces-default-encryption"
  control_ids    = ["SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    encryption_type    = "AES-256"
    provider_managed   = "true"
    user_managed_keys  = "false"
    encryption_enabled = "true"
  }
}
