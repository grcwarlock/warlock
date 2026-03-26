###############################################################################
# DigitalOcean Monitoring — CPU/Memory Alerts + Uptime Checks
# Enforces: AU-2 (Auditable Events)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.34" }
  }
}

# -- AU-2: CPU Alert -----------------------------------------------------------

resource "digitalocean_monitor_alert" "cpu" {
  for_each = toset(var.droplet_ids)

  alerts {
    email = [var.alert_email]
  }

  window      = "5m"
  type        = "v1/insights/droplet/cpu"
  compare     = "GreaterThan"
  value       = 90
  enabled     = true
  entities    = [each.value]
  description = "${var.name_prefix}-cpu-alert-${each.value}"
  tags        = var.tags
}

# -- AU-2: Memory Alert --------------------------------------------------------

resource "digitalocean_monitor_alert" "memory" {
  for_each = toset(var.droplet_ids)

  alerts {
    email = [var.alert_email]
  }

  window      = "5m"
  type        = "v1/insights/droplet/memory_utilization_percent"
  compare     = "GreaterThan"
  value       = 90
  enabled     = true
  entities    = [each.value]
  description = "${var.name_prefix}-memory-alert-${each.value}"
  tags        = var.tags
}

# -- AU-2: Uptime Checks ------------------------------------------------------

resource "digitalocean_uptime_check" "main" {
  for_each = toset(var.droplet_ids)

  name    = "${var.name_prefix}-uptime-${each.value}"
  target  = each.value
  type    = "https"
  regions = ["us_east", "eu_west"]
  enabled = true
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/digitalocean-monitoring"
  resource_id    = "${var.name_prefix}-monitoring"
  control_ids    = ["AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    alert_email   = var.alert_email
    droplet_count = tostring(length(var.droplet_ids))
  }
}
