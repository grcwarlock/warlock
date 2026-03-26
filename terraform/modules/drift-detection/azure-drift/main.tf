###############################################################################
# Azure Drift Detection Baseline
# Enforces: CM-3 (Change Control), CM-8 (Component Inventory)
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

# -- CM-8: Resource group for drift detection resources ------------------------

resource "azurerm_resource_group" "drift" {
  name     = "${var.name_prefix}-drift-detection-rg"
  location = var.location
  tags     = merge(local.common_tags, { Name = "${var.name_prefix}-drift-detection-rg" })
}

# -- CM-3: Log Analytics workspace for drift results ---------------------------

resource "azurerm_log_analytics_workspace" "drift" {
  name                = "${var.name_prefix}-drift-law"
  location            = azurerm_resource_group.drift.location
  resource_group_name = azurerm_resource_group.drift.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.common_tags
}

# -- CM-3: Automation account for scheduled drift checks -----------------------

resource "azurerm_automation_account" "drift" {
  name                = "${var.name_prefix}-drift-aa"
  location            = azurerm_resource_group.drift.location
  resource_group_name = azurerm_resource_group.drift.name
  sku_name            = "Basic"
  tags                = local.common_tags
}

# -- CM-3: Recurring schedule for drift detection ------------------------------

resource "azurerm_automation_schedule" "drift" {
  name                    = "${var.name_prefix}-drift-schedule"
  resource_group_name     = azurerm_resource_group.drift.name
  automation_account_name = azurerm_automation_account.drift.name
  frequency               = var.schedule_frequency
  interval                = var.schedule_interval
  description             = "Recurring schedule for infrastructure drift detection"
}

# -- CM-3/CM-8: Runbook comparing Azure Policy compliance state ----------------

resource "azurerm_automation_runbook" "drift" {
  name                    = "${var.name_prefix}-drift-check"
  location                = azurerm_resource_group.drift.location
  resource_group_name     = azurerm_resource_group.drift.name
  automation_account_name = azurerm_automation_account.drift.name
  log_verbose             = true
  log_progress            = true
  runbook_type            = "PowerShell"
  description             = "Compares Azure Policy compliance state to detect infrastructure drift"
  tags                    = local.common_tags

  content = <<-PS
    # Drift Detection Runbook — CM-3/CM-8
    # Queries Azure Policy compliance and reports non-compliant resources.

    Connect-AzAccount -Identity

    $nonCompliant = Get-AzPolicyState -Filter "ComplianceState eq 'NonCompliant'" `
      | Select-Object ResourceId, PolicyDefinitionName, ComplianceState, Timestamp

    if ($nonCompliant.Count -gt 0) {
      Write-Output "DRIFT DETECTED: $($nonCompliant.Count) non-compliant resources found."
      $nonCompliant | ConvertTo-Json -Depth 5
    } else {
      Write-Output "NO DRIFT: All resources compliant."
    }
  PS
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "drift-detection/azure-drift"
  resource_id    = azurerm_automation_account.drift.id
  control_ids    = ["CM-3", "CM-8"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    schedule_frequency = var.schedule_frequency
    schedule_interval  = tostring(var.schedule_interval)
    runbook_type       = "PowerShell"
  }
}
