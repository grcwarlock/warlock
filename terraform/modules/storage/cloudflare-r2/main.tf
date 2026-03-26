###############################################################################
# Cloudflare R2 Object Storage
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 4.20" }
  }
}

# -- SC-28/AC-3: R2 bucket (encrypted at rest by default) --------------------

resource "cloudflare_r2_bucket" "main" {
  account_id = var.account_id
  name       = var.bucket_name
  location   = var.location
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/cloudflare-r2"
  resource_id    = cloudflare_r2_bucket.main.id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    bucket_name = var.bucket_name
    location    = var.location
    encryption  = "provider-managed"
  }
}
