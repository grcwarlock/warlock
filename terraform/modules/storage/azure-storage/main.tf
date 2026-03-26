###############################################################################
# Azure Storage Account Hardening
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
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

# -- SC-28/AC-3: Storage account with HTTPS, TLS 1.2, GRS replication ---------

resource "azurerm_storage_account" "main" {
  name                     = "${var.name_prefix}sa"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GRS" # SC-28: geo-redundant replication

  https_traffic_only_enabled = true     # SC-28: HTTPS only
  min_tls_version            = "TLS1_2" # SC-28: minimum TLS 1.2

  blob_properties {
    delete_retention_policy {
      days = 30 # SC-28: soft delete for blobs
    }
    container_delete_retention_policy {
      days = 30 # SC-28: soft delete for containers
    }
  }

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-storage-account" })
}

# -- AC-3: Network rules — default deny, allow Azure Services -----------------

resource "azurerm_storage_account_network_rules" "main" {
  storage_account_id = azurerm_storage_account.main.id

  default_action             = "Deny"            # AC-3: deny by default
  bypass                     = ["AzureServices"] # AC-3: allow Azure platform services
  ip_rules                   = var.allowed_ip_ranges
  virtual_network_subnet_ids = var.allowed_subnet_ids
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/azure-storage"
  resource_id    = azurerm_storage_account.main.id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    https_only             = "true"
    min_tls_version        = "TLS1_2"
    replication_type       = "GRS"
    blob_soft_delete       = "30"
    network_default_action = "Deny"
  }
}
