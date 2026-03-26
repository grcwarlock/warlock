###############################################################################
# Azure Container Registry Hardening Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Management),
#           SI-3 (Malicious Code Protection)
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

# -- SC-28/CM-6/SI-3: Azure Container Registry with Premium hardening ----------

resource "azurerm_container_registry" "main" {
  name                = "${var.name_prefix}acr"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = var.sku
  admin_enabled       = false # CM-6: disable admin user, use RBAC
  tags                = merge(local.common_tags, { Name = "${var.name_prefix}-acr" })

  retention_policy {
    enabled = true
    days    = 30 # CM-6: retain untagged manifests for 30 days
  }

  trust_policy {
    enabled = true # SI-3: enable content trust for image signing
  }

  dynamic "georeplications" {
    for_each = var.georeplication_locations
    content {
      location = georeplications.value
      tags     = local.common_tags
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "container/azure-acr"
  resource_id    = azurerm_container_registry.main.id
  control_ids    = ["SC-28", "CM-6", "SI-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    sku            = var.sku
    admin_enabled  = "false"
    content_trust  = "true"
    retention_days = "30"
  }
}
