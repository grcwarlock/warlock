###############################################################################
# Azure Key Vault Baseline
# Enforces: SC-12 (Cryptographic Key Management), SC-28 (Encryption at Rest)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
  }
}

data "azurerm_client_config" "current" {}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- Key Vault with RBAC, purge protection, soft delete ------------------------

resource "azurerm_key_vault" "main" {
  name                       = "${var.name_prefix}-kv"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = var.sku_name
  soft_delete_retention_days = var.soft_delete_retention_days
  purge_protection_enabled   = true # SC-12: mandatory, prevents permanent key loss
  enable_rbac_authorization  = true # SC-12: use Azure RBAC instead of vault access policies

  network_acls {
    bypass                     = "AzureServices"
    default_action             = var.network_default_action
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-key-vault" })
}

# -- SC-12: RBAC — grant caller identity Key Vault Administrator ---------------

resource "azurerm_role_assignment" "kv_admin" {
  count                = var.grant_caller_admin ? 1 : 0
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# -- AU-2: Diagnostic settings -> Log Analytics --------------------------------

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  count                      = var.log_analytics_workspace_id != null ? 1 : 0
  name                       = "${var.name_prefix}-kv-diagnostics"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "AuditEvent" }
  enabled_log { category = "AzurePolicyEvaluationDetails" }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# -- SC-7: Private endpoint (optional) ----------------------------------------

resource "azurerm_private_endpoint" "key_vault" {
  count               = var.private_endpoint_subnet_id != null ? 1 : 0
  name                = "${var.name_prefix}-kv-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id
  tags                = local.common_tags

  private_service_connection {
    name                           = "${var.name_prefix}-kv-psc"
    private_connection_resource_id = azurerm_key_vault.main.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/azure-keyvault"
  resource_id    = azurerm_key_vault.main.id
  control_ids    = ["SC-12", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    purge_protection_enabled   = "true"
    rbac_authorization_enabled = "true"
    soft_delete_retention_days = tostring(var.soft_delete_retention_days)
  }
}
