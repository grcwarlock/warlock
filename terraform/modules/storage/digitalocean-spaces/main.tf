###############################################################################
# DigitalOcean Spaces Bucket
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.34" }
  }
}

# -- SC-28/AC-3: Spaces bucket with private ACL --------------------------------

resource "digitalocean_spaces_bucket" "main" {
  name          = "${var.name_prefix}-spaces"
  region        = var.region
  acl           = var.acl
  force_destroy = false # SC-28: prevent accidental data loss
}

# -- AC-3: Optional CORS configuration ----------------------------------------

resource "digitalocean_spaces_bucket_cors_configuration" "main" {
  count  = length(var.cors_rules) > 0 ? 1 : 0
  bucket = digitalocean_spaces_bucket.main.id
  region = var.region

  dynamic "cors_rule" {
    for_each = var.cors_rules
    content {
      allowed_headers = cors_rule.value.allowed_headers
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      max_age_seconds = cors_rule.value.max_age_seconds
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/digitalocean-spaces"
  resource_id    = digitalocean_spaces_bucket.main.urn
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    acl              = var.acl
    force_destroy    = "false"
    encryption       = "provider-managed-aes-256"
    cors_rules_count = tostring(length(var.cors_rules))
  }
}
