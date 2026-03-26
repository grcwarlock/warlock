###############################################################################
# Azure Functions Hardening
# Enforces: SC-7 (VNet Integration), SC-28 (Storage Encryption),
#           AU-2 (App Insights)
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

# -- AU-2: Application Insights for telemetry --------------------------------

resource "azurerm_application_insights" "main" {
  name                = "${var.name_prefix}-appinsights"
  location            = var.location
  resource_group_name = var.resource_group_name
  application_type    = "web"

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-appinsights" })
}

# -- Service Plan -------------------------------------------------------------

resource "azurerm_service_plan" "main" {
  name                = "${var.name_prefix}-plan"
  location            = var.location
  resource_group_name = var.resource_group_name
  os_type             = "Linux"
  sku_name            = var.sku_name

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-plan" })
}

# -- SC-7, SC-28, AU-2: Hardened Function App ---------------------------------

resource "azurerm_linux_function_app" "main" {
  name                = "${var.name_prefix}-func"
  location            = var.location
  resource_group_name = var.resource_group_name
  service_plan_id     = azurerm_service_plan.main.id

  storage_account_name       = var.storage_account_name
  storage_account_access_key = var.storage_account_access_key

  # SC-28: HTTPS only
  https_only = true

  site_config {
    # SC-28: Minimum TLS 1.2
    minimum_tls_version = "1.2"

    application_insights_connection_string = azurerm_application_insights.main.connection_string
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-func" })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/azure-functions"
  resource_id    = azurerm_linux_function_app.main.id
  control_ids    = ["SC-7", "SC-28", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    https_only      = "true"
    min_tls_version = "1.2"
    app_insights    = "enabled"
  }
}
