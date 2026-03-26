###############################################################################
# Cloudflare WAF — Managed Rulesets (OWASP + Cloudflare Managed)
# Enforces: SC-7 (Boundary Protection), SI-3 (Malicious Code Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 4.20" }
  }
}

# -- SC-7/SI-3: Deploy managed WAF rulesets -----------------------------------

resource "cloudflare_ruleset" "waf_managed" {
  zone_id = var.zone_id
  name    = "${var.name_prefix}-waf-managed"
  kind    = "zone"
  phase   = "http_request_firewall_managed"

  # Cloudflare Managed Ruleset
  rules {
    action = "execute"
    action_parameters {
      id = "efb7b8c949ac4650a09736fc376e9aee" # Cloudflare Managed Ruleset
    }
    expression  = "true"
    description = "Deploy Cloudflare Managed Ruleset"
    enabled     = true
  }

  # OWASP Core Ruleset (optional)
  dynamic "rules" {
    for_each = var.enable_owasp ? [1] : []
    content {
      action = "execute"
      action_parameters {
        id = "4814384a9e5d4991b9815dcfc25d2f1f" # Cloudflare OWASP Core Ruleset
      }
      expression  = "true"
      description = "Deploy Cloudflare OWASP Core Ruleset"
      enabled     = true
    }
  }
}

# -- SC-7: Zone security settings ---------------------------------------------

resource "cloudflare_zone_settings_override" "waf" {
  zone_id = var.zone_id

  settings {
    waf            = "on"
    security_level = var.security_level
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/cloudflare-waf"
  resource_id    = cloudflare_ruleset.waf_managed.id
  control_ids    = ["SC-7", "SI-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    owasp_enabled  = tostring(var.enable_owasp)
    security_level = var.security_level
    waf_enabled    = "true"
  }
}
