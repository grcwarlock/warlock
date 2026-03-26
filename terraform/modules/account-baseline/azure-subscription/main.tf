###############################################################################
# Azure Secure Subscription Baseline
# Enforces: AU-2 (Activity Log), AU-6 (Defender), SC-28 (Encryption)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
  }
}

locals {
  common_tags = merge(var.tags, { ManagedBy = "warlock" })
}

data "azurerm_subscription" "current" {}

# -- Resource Group -----------------------------------------------------------

resource "azurerm_resource_group" "security" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.common_tags
}

# -- AU-2: Log Analytics Workspace -------------------------------------------

resource "azurerm_log_analytics_workspace" "security" {
  name                = "${var.name_prefix}-security-logs"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.common_tags
}

# -- AU-2: Activity Log Diagnostic Setting -----------------------------------

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "activity-log-to-analytics"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Policy" }
}

# -- SC-28: Storage Account for Security Logs --------------------------------

resource "azurerm_storage_account" "security_logs" {
  name                      = var.storage_account_name
  resource_group_name       = azurerm_resource_group.security.name
  location                  = azurerm_resource_group.security.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true
  tags                      = local.common_tags

  blob_properties {
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
}

# -- Network Watcher ---------------------------------------------------------

resource "azurerm_network_watcher" "main" {
  name                = "${var.name_prefix}-network-watcher"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  tags                = local.common_tags
}

# -- Microsoft Defender for Cloud --------------------------------------------

resource "azurerm_security_center_subscription_pricing" "servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "sql" {
  tier          = "Standard"
  resource_type = "SqlServers"
}

resource "azurerm_security_center_subscription_pricing" "app_services" {
  tier          = "Standard"
  resource_type = "AppServices"
}

resource "azurerm_security_center_subscription_pricing" "key_vaults" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_contact" "main" {
  email               = var.security_contact_email
  alert_notifications = true
  alerts_to_admins    = true
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "account-baseline/azure-subscription"
  resource_id    = azurerm_resource_group.security.id
  control_ids    = ["AU-2", "AU-6", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    resource_group     = var.resource_group_name
    location           = var.location
    log_retention_days = tostring(var.log_retention_days)
  }
}
