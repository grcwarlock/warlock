###############################################################################
# Scaleway Secret Manager — LIMITED (no dedicated KMS)
# Enforces: SC-12 (Cryptographic Key Management)
#
# Scaleway does not offer a dedicated KMS service. This module uses Secret
# Manager for secret storage. See remediation.tf for limitations.
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    scaleway = { source = "scaleway/scaleway", version = "~> 2.30" }
  }
}

# -- SC-12: Secret resource ---------------------------------------------------

resource "scaleway_secret" "main" {
  name        = "${var.name_prefix}-${var.secret_name}"
  project_id  = var.project_id
  description = "Managed by Warlock GRC platform"
  tags        = concat(var.tags, ["managed-by:warlock", "framework:nist-800-53"])
}

# -- SC-12: Secret version with sensitive data --------------------------------

resource "scaleway_secret_version" "main" {
  secret_id = scaleway_secret.main.id
  data      = var.secret_data
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/scaleway-secret-manager"
  resource_id    = scaleway_secret.main.id
  control_ids    = ["SC-12"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    secret_name = "${var.name_prefix}-${var.secret_name}"
    project_id  = var.project_id
    note        = "Scaleway has no dedicated KMS. Using Secret Manager."
  }
}
