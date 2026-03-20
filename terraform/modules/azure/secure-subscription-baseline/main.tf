###############################################################################
# Azure Secure Subscription Baseline
# Enforces: AU-2 (Activity Log), AU-6 (Defender), SC-28 (Encryption)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    # T-5: Azure provider upgrade path — ~> 3.80 → ~> 4.0
    # When upgrading to azurerm ~> 4.0:
    #   - The `enable_https_traffic_only` argument on azurerm_storage_account
    #     is removed; HTTPS-only is enforced by default in v4.
    #   - The `azurerm_security_center_contact` resource gained `name` as a
    #     required argument in v4 (previously defaulted to "default").
    #   - `azurerm_monitor_diagnostic_setting` changed `enabled_log` blocks:
    #     the `retention_policy` sub-block is removed; use log analytics
    #     workspace retention settings instead.
    #   - Run `terraform plan` after upgrading to catch any additional
    #     provider-level breaking changes surfaced by the azurerm 4.x
    #     migration guide: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/4.0-upgrade-guide
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
  }
}

locals {
  common_tags = merge(var.tags, { ManagedBy = "warlock" })
}

# T-8: The azurerm_subscription data source requires the caller identity to hold
# at least the built-in "Reader" role at the subscription scope.
# If running in a pipeline, ensure the service principal has:
#   - Role: Reader (scope: /subscriptions/<subscription_id>)
# Without this, the data source will return a 403 and the plan will fail.
data "azurerm_subscription" "current" {}

# ── Resource Group ────────────────────────────────────────────────────

resource "azurerm_resource_group" "security" {
  name     = var.resource_group_name
  location = var.location
  tags     = local.common_tags
}

# ── AU-2: Log Analytics Workspace ─────────────────────────────────────

resource "azurerm_log_analytics_workspace" "security" {
  name                = "${var.name_prefix}-security-logs"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.common_tags
}

# ── AU-2: Activity Log Diagnostic Setting ─────────────────────────────

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "activity-log-to-analytics"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  enabled_log { category = "Administrative" }
  enabled_log { category = "Security" }
  enabled_log { category = "Alert" }
  enabled_log { category = "Policy" }
}

# ── SC-28: Storage Account for Security Logs ─────────────────────────

resource "azurerm_storage_account" "security_logs" {
  name                      = var.storage_account_name
  resource_group_name       = azurerm_resource_group.security.name
  location                  = azurerm_resource_group.security.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = true
  tags                      = local.common_tags

  # T-15: Enable blob and container soft-delete to protect against accidental deletion
  blob_properties {
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }
}

# ── Network Watcher ───────────────────────────────────────────────────

resource "azurerm_network_watcher" "main" {
  name                = "${var.name_prefix}-network-watcher"
  location            = azurerm_resource_group.security.location
  resource_group_name = azurerm_resource_group.security.name
  tags                = local.common_tags
}

# ── Microsoft Defender for Cloud ─────────────────────────────────────
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

# ── #41: Warlock self-registration evidence ───────────────────────────

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration evidence. Set to null to disable."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API authentication."
  type        = string
  default     = null
  sensitive   = true
}

resource "terraform_data" "warlock_evidence" {
  count = var.warlock_api_endpoint != null ? 1 : 0

  triggers_replace = [azurerm_resource_group.security.id]

  provisioner "local-exec" {
    environment = {
      WARLOCK_API_ENDPOINT = var.warlock_api_endpoint
      WARLOCK_API_TOKEN    = var.warlock_api_token
    }
    command = <<-EOT
      curl -sf -X POST "$WARLOCK_API_ENDPOINT/api/v1/evidence" \
        -H "Authorization: Bearer $WARLOCK_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "module": "azure/secure-subscription-baseline",
          "resource_id": "${azurerm_resource_group.security.id}",
          "control_ids": ["AU-2", "AU-6", "SC-28"],
          "attributes": {
            "resource_group": "${var.resource_group_name}",
            "location": "${var.location}",
            "log_retention_days": ${var.log_retention_days}
          }
        }' || true
    EOT
  }
}
