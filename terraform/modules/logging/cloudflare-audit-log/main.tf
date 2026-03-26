###############################################################################
# Cloudflare Logpush — Audit Log Forwarding
# Enforces: AU-2 (Auditable Events)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    cloudflare = { source = "cloudflare/cloudflare", version = "~> 4.20" }
  }
}

# -- AU-2: Logpush job for HTTP requests or firewall events -------------------

resource "cloudflare_logpush_job" "main" {
  zone_id          = var.zone_id
  name             = "${var.name_prefix}-logpush"
  enabled          = true
  dataset          = var.dataset
  destination_conf = var.destination_conf
  logpull_options  = "fields=ClientIP,ClientRequestHost,ClientRequestMethod,ClientRequestURI,EdgeStartTimestamp,EdgeResponseStatus&timestamps=rfc3339"
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/cloudflare-audit-log"
  resource_id    = cloudflare_logpush_job.main.id
  control_ids    = ["AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    dataset          = var.dataset
    destination_type = "logpush"
  }
}
