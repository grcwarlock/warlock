###############################################################################
# OCI Vault + KMS Key Baseline
# Enforces: SC-12 (Cryptographic Key Management), SC-28 (Encryption at Rest)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 5.0" }
  }
}

locals {
  common_tags = merge(var.tags, { managed_by = "warlock" })
}

# -- SC-12: OCI Vault ---------------------------------------------------------

resource "oci_kms_vault" "main" {
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}-vault"
  vault_type     = "DEFAULT"

  freeform_tags = local.common_tags
}

# -- SC-12/SC-28: Master Encryption Key (HSM-backed, AES-256) -----------------

resource "oci_kms_key" "main" {
  compartment_id  = var.compartment_id
  display_name    = "${var.name_prefix}-master-key"
  protection_mode = "HSM"

  key_shape {
    algorithm = "AES"
    length    = 32
  }

  management_endpoint = oci_kms_vault.main.management_endpoint

  freeform_tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/oci-vault"
  resource_id    = oci_kms_key.main.id
  control_ids    = ["SC-12", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    vault_type      = "DEFAULT"
    algorithm       = "AES"
    key_length      = "32"
    protection_mode = "HSM"
  }
}
