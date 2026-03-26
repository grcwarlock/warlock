###############################################################################
# Azure Defender for Cloud Baseline
# Enforces: SI-3 (Malicious Code Protection), SI-4 (System Monitoring),
#           AU-6 (Audit Review)
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

  defender_resource_types = toset([
    "VirtualMachines",
    "StorageAccounts",
    "SqlServers",
    "AppServices",
    "KeyVaults",
  ])
}

# -- SI-3/SI-4: Enable Defender for Cloud on each resource type ----------------

resource "azurerm_security_center_subscription_pricing" "defender" {
  for_each      = local.defender_resource_types
  tier          = "Standard"
  resource_type = each.value
}

# -- AU-6: Security contact for alert notifications ----------------------------

resource "azurerm_security_center_contact" "main" {
  email               = var.security_contact_email
  phone               = var.security_contact_phone
  alert_notifications = true
  alerts_to_admins    = true
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/azure-defender"
  resource_id    = "azure-defender-subscription"
  control_ids    = ["SI-3", "SI-4", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    security_contact_email = var.security_contact_email
    resource_types         = join(",", local.defender_resource_types)
  }
}
