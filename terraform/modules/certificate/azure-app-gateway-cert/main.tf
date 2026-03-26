###############################################################################
# Azure Key Vault Certificate Management Baseline
# Enforces: SC-17 (PKI Certificates), SC-23 (Session Authenticity)
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

# -- SC-17: Key Vault certificate (self-signed or imported) --------------------

resource "azurerm_key_vault_certificate" "main" {
  name         = var.certificate_name
  key_vault_id = var.key_vault_id
  tags         = merge(local.common_tags, { Name = "${var.name_prefix}-cert" })

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }

      trigger {
        days_before_expiry = 30
      }
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }

    x509_certificate_properties {
      subject            = "CN=${var.common_name}"
      validity_in_months = var.validity_in_months

      key_usage = [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyAgreement",
        "keyCertSign",
        "keyEncipherment",
      ]
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "certificate/azure-app-gateway-cert"
  resource_id    = azurerm_key_vault_certificate.main.id
  control_ids    = ["SC-17", "SC-23"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    certificate_name   = var.certificate_name
    common_name        = var.common_name
    validity_in_months = tostring(var.validity_in_months)
  }
}
