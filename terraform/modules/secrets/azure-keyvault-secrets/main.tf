###############################################################################
# Azure Key Vault Secret Management
# Enforces: SC-12 (Key Management), IA-5 (Authenticator Management)
# Note: Manages secrets WITHIN an existing Key Vault (separate from
#       encryption/azure-keyvault which manages the vault itself).
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

# -- SC-12/IA-5: Key Vault secret with content type and expiration -------------

resource "azurerm_key_vault_secret" "main" {
  name            = var.secret_name
  value           = var.secret_value
  key_vault_id    = var.key_vault_id
  content_type    = var.content_type
  expiration_date = var.expiration_date # IA-5: enforce expiration

  tags = merge(local.common_tags, { Name = var.secret_name })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "secrets/azure-keyvault-secrets"
  resource_id    = azurerm_key_vault_secret.main.id
  control_ids    = ["SC-12", "IA-5"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    content_type    = var.content_type
    has_expiration  = tostring(var.expiration_date != null)
    expiration_date = coalesce(var.expiration_date, "none")
  }
}
