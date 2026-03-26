###############################################################################
# Cloudflare Access — Zero Trust Application + Policy
# Enforces: AC-2 (Account Management), AC-3 (Access Enforcement)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 4.20" }
  }
}

# -- AC-2/AC-3: Access Application --------------------------------------------

resource "cloudflare_access_application" "main" {
  zone_id          = var.zone_id
  name             = var.app_name
  domain           = var.domain
  session_duration = var.session_duration
  type             = "self_hosted"
}

# -- AC-3: Access Policy — allow by email domain ------------------------------

resource "cloudflare_access_policy" "allow_email_domain" {
  zone_id        = var.zone_id
  application_id = cloudflare_access_application.main.id
  name           = "${var.app_name}-allow-email-domain"
  precedence     = 1
  decision       = "allow"

  include {
    email_domain = var.allowed_email_domains
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/cloudflare-access"
  resource_id    = cloudflare_access_application.main.id
  control_ids    = ["AC-2", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    app_name              = var.app_name
    domain                = var.domain
    session_duration      = var.session_duration
    allowed_email_domains = join(",", var.allowed_email_domains)
  }
}
