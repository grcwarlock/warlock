###############################################################################
# Azure Activity Log + Diagnostics
# Enforces: AU-2 (Event Logging), AU-6 (Audit Review)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
  create_workspace = var.log_analytics_workspace_id == null
}

# -- AU-6: Log Analytics Workspace (created if not provided) ------------------

resource "azurerm_log_analytics_workspace" "main" {
  count               = local.create_workspace ? 1 : 0
  name                = "${var.name_prefix}-law"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-log-analytics" })
}

locals {
  workspace_id = local.create_workspace ? azurerm_log_analytics_workspace.main[0].id : var.log_analytics_workspace_id
}

# -- AU-2: Diagnostic Setting on Subscription --------------------------------

resource "azurerm_monitor_diagnostic_setting" "subscription" {
  name                       = "${var.name_prefix}-activity-log-diag"
  target_resource_id         = "/subscriptions/${var.subscription_id}"
  log_analytics_workspace_id = local.workspace_id

  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Policy" }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/azure-activity-log"
  resource_id    = azurerm_monitor_diagnostic_setting.subscription.id
  control_ids    = ["AU-2", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    log_retention_days = tostring(var.log_retention_days)
    subscription_id    = var.subscription_id
    categories         = "Administrative,Security,Alert,Policy"
  }
}
