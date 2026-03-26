###############################################################################
# Scaleway Cockpit (Observability)
# Enforces: AU-2 (Audit Logging)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    scaleway = { source = "scaleway/scaleway", version = "~> 2.30" }
  }
}

# -- AU-2: Enable Cockpit for the project ------------------------------------

resource "scaleway_cockpit" "main" {
  project_id = var.project_id
}

# -- AU-2: Optional Grafana admin user for dashboard access -------------------

resource "scaleway_cockpit_grafana_user" "admin" {
  count = var.grafana_admin_login != null ? 1 : 0

  project_id = var.project_id
  login      = var.grafana_admin_login
  role       = "editor"

  depends_on = [scaleway_cockpit.main]
}

# -- AU-2: Optional data source for log ingestion ----------------------------

resource "scaleway_cockpit_source" "logs" {
  count = var.enable_log_source ? 1 : 0

  project_id     = var.project_id
  name           = "${var.name_prefix}-logs"
  type           = "logs"
  retention_days = var.log_retention_days

  depends_on = [scaleway_cockpit.main]
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/scaleway-cockpit"
  resource_id    = scaleway_cockpit.main.id
  control_ids    = ["AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    project_id         = var.project_id
    grafana_configured = var.grafana_admin_login != null ? "true" : "false"
    log_source_enabled = tostring(var.enable_log_source)
  }
}
