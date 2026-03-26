###############################################################################
# Hetzner Storage Box — STUB
# Enforces: SC-28 (Encryption at Rest)
#
# Hetzner Storage Boxes cannot be managed via Terraform. They must be ordered
# and configured through the Hetzner Robot panel. See remediation.tf.
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
  module_name    = "storage/hetzner-storage-box"
  resource_id    = "stub-hetzner-storage-box"
  control_ids    = ["SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    stub = "true"
  }
}
