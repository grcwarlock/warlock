###############################################################################
# Azure Entra ID (AAD) Hardening
# Enforces: AC-2 (Account Management), IA-2 (Identification), AC-6 (Least Privilege)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
    azuread = { source = "hashicorp/azuread", version = "~> 2.47" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- AC-2: Managed Identity for workloads ------------------------------------

resource "azurerm_user_assigned_identity" "main" {
  name                = "${var.name_prefix}-identity"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-managed-identity" })
}

# -- AC-2/AC-6: Security group for RBAC --------------------------------------

resource "azuread_group" "main" {
  display_name     = var.group_display_name
  mail_enabled     = false
  security_enabled = true
}

# -- AC-2: Group members (optional) ------------------------------------------

resource "azuread_group_member" "members" {
  for_each = toset(var.group_members)

  group_object_id  = azuread_group.main.object_id
  member_object_id = each.value
}

# -- IA-2: Conditional Access — require MFA (optional, requires Azure AD P1) --

resource "azuread_conditional_access_policy" "require_mfa" {
  count = var.enable_conditional_access_mfa ? 1 : 0

  display_name = "${var.name_prefix}-require-mfa"
  state        = "enabled"

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_groups = [azuread_group.main.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/azure-entra"
  resource_id    = azurerm_user_assigned_identity.main.id
  control_ids    = ["AC-2", "IA-2", "AC-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    managed_identity_name  = azurerm_user_assigned_identity.main.name
    security_group         = azuread_group.main.display_name
    conditional_access_mfa = tostring(var.enable_conditional_access_mfa)
  }
}
