###############################################################################
# Cloudflare SSL/TLS Hardening
# Enforces: SC-17 (PKI Certificates), SC-23 (Session Authenticity)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 4.20" }
  }
}

# -- SC-17/SC-23: Strict SSL, HTTPS enforcement, TLS 1.2+ --------------------

resource "cloudflare_zone_settings_override" "ssl" {
  zone_id = var.zone_id

  settings {
    ssl                      = "strict"
    always_use_https         = "on"
    min_tls_version          = var.min_tls_version
    tls_1_3                  = "on"
    automatic_https_rewrites = "on"
  }
}

# -- SC-23: Optional authenticated origin pulls -------------------------------

resource "cloudflare_authenticated_origin_pulls" "main" {
  count   = var.enable_origin_pulls ? 1 : 0
  zone_id = var.zone_id
  enabled = true
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/cloudflare-ssl"
  resource_id    = var.zone_id
  control_ids    = ["SC-17", "SC-23"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    ssl_mode             = "strict"
    always_use_https     = "on"
    min_tls_version      = var.min_tls_version
    tls_1_3              = "on"
    origin_pulls_enabled = tostring(var.enable_origin_pulls)
  }
}
