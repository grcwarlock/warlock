###############################################################################
# Warlock Connector Provisioning — Azure
# Provisions service principal, Key Vault, and diagnostic settings
# for Warlock connector access to Azure subscriptions.
# Enforces: AC-2 (Account Management), AC-3 (Access Enforcement),
#           SC-12 (Cryptographic Key Management), AU-3 (Content of Audit Records)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.0" }
    azuread = { source = "hashicorp/azuread", version = "~> 2.0" }
  }
}

data "azurerm_subscription" "current" {}
data "azuread_client_config" "current" {}

locals {
  common_tags = merge(var.tags, {
    managed_by = "warlock"
    component  = "connector-provisioning"
  })
  name_prefix = "${var.name_prefix}-connector"
}

# -- Azure AD Application + Service Principal ---------------------------------

resource "azuread_application" "warlock_connector" {
  display_name = "${local.name_prefix}-app"

  owners = [data.azuread_client_config.current.object_id]

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
      type = "Scope"
    }
  }

  tags = ["warlock", "connector-provisioning"]
}

resource "azuread_service_principal" "warlock_connector" {
  client_id                    = azuread_application.warlock_connector.client_id
  app_role_assignment_required = false

  owners = [data.azuread_client_config.current.object_id]

  tags = ["warlock", "connector-provisioning"]
}

resource "azuread_application_password" "warlock_connector" {
  count          = var.create_client_secret ? 1 : 0
  application_id = azuread_application.warlock_connector.id
  display_name   = "warlock-connector-secret"
  end_date       = var.client_secret_end_date
}

# -- Reader role assignment on subscription -----------------------------------

resource "azurerm_role_assignment" "reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.warlock_connector.object_id
}

resource "azurerm_role_assignment" "security_reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Security Reader"
  principal_id         = azuread_service_principal.warlock_connector.object_id
}

# -- Key Vault for connector credentials --------------------------------------

resource "azurerm_resource_group" "warlock" {
  name     = "${local.name_prefix}-rg"
  location = var.location

  tags = local.common_tags
}

resource "azurerm_key_vault" "connector" {
  name                        = "${var.name_prefix}connkv"
  location                    = azurerm_resource_group.warlock.location
  resource_group_name         = azurerm_resource_group.warlock.name
  tenant_id                   = data.azuread_client_config.current.tenant_id
  sku_name                    = "standard"
  enabled_for_disk_encryption = false
  purge_protection_enabled    = true
  soft_delete_retention_days  = 90

  # Allow the deployer to manage secrets
  access_policy {
    tenant_id = data.azuread_client_config.current.tenant_id
    object_id = data.azuread_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Purge", "Recover",
    ]
    key_permissions = [
      "Get", "List", "Create", "Delete", "Purge", "Recover",
    ]
  }

  # Allow Warlock service principal to read secrets
  access_policy {
    tenant_id = data.azuread_client_config.current.tenant_id
    object_id = azuread_service_principal.warlock_connector.object_id

    secret_permissions = ["Get", "List"]
    key_permissions    = ["Get", "List"]
  }

  tags = local.common_tags
}

# -- Diagnostic settings export to Warlock ------------------------------------

resource "azurerm_monitor_diagnostic_setting" "keyvault_audit" {
  name               = "${local.name_prefix}-kv-diagnostics"
  target_resource_id = azurerm_key_vault.connector.id

  enabled_log {
    category = "AuditEvent"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }

  # Export to a Log Analytics workspace if provided
  log_analytics_workspace_id = var.log_analytics_workspace_id
}

# -- Warlock self-registration ------------------------------------------------

