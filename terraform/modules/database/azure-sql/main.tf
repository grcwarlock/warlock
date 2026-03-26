###############################################################################
# Azure SQL Hardening
# Enforces: SC-28 (Encryption at Rest), AU-2 (Audit Logging), SC-7 (Network)
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
}

# -- SC-28/SC-7: MSSQL Server with TLS 1.2, private access --------------------

resource "azurerm_mssql_server" "main" {
  name                         = "${var.name_prefix}-sqlserver"
  resource_group_name          = var.resource_group_name
  location                     = var.location
  version                      = "12.0"
  administrator_login          = var.administrator_login
  administrator_login_password = var.administrator_login_password

  minimum_tls_version           = "1.2" # SC-28: minimum TLS 1.2
  public_network_access_enabled = false # SC-7: no public access

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-sql-server" })
}

# -- SC-28: Transparent Data Encryption ---------------------------------------

resource "azurerm_mssql_server_transparent_data_encryption" "main" {
  server_id = azurerm_mssql_server.main.id
}

# -- SC-28: MSSQL Database ----------------------------------------------------

resource "azurerm_mssql_database" "main" {
  name      = "${var.name_prefix}-db"
  server_id = azurerm_mssql_server.main.id
  sku_name  = var.sku_name

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-sql-database" })
}

# -- SC-7: Firewall rules (optional) ------------------------------------------

resource "azurerm_mssql_firewall_rule" "allow_azure" {
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# -- AU-2: Extended auditing policy --------------------------------------------

resource "azurerm_mssql_server_extended_auditing_policy" "main" {
  server_id              = azurerm_mssql_server.main.id
  retention_in_days      = 90 # AU-2: retain audit logs for 90 days
  log_monitoring_enabled = true
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "database/azure-sql"
  resource_id    = azurerm_mssql_server.main.id
  control_ids    = ["SC-28", "AU-2", "SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    minimum_tls_version         = "1.2"
    public_network_access       = "false"
    transparent_data_encryption = "true"
    audit_retention_days        = "90"
  }
}
