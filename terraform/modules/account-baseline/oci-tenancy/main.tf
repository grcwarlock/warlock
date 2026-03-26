###############################################################################
# OCI Tenancy Baseline (Composite)
# Enforces: AU-2 (Audit Logging), AC-3 (Access Enforcement),
#           SC-28 (Encryption at Rest)
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

# -- AU-2: Audit Log Group and Service Log ------------------------------------

resource "oci_logging_log_group" "audit" {
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}-tenancy-audit-logs"
  description    = "Warlock-managed tenancy-level audit log group"

  freeform_tags = local.common_tags
}

resource "oci_logging_log" "audit" {
  display_name = "${var.name_prefix}-tenancy-audit"
  log_group_id = oci_logging_log_group.audit.id
  log_type     = "SERVICE"
  is_enabled   = true

  configuration {
    source {
      category    = "audit"
      resource    = var.tenancy_id
      service     = "audit"
      source_type = "OCISERVICE"
    }
    compartment_id = var.compartment_id
  }

  freeform_tags = local.common_tags
}

# -- AC-3: IAM Authentication Policy (password complexity) --------------------

resource "oci_identity_authentication_policy" "strict" {
  compartment_id = var.tenancy_id

  password_policy {
    is_lowercase_characters_required = true
    is_uppercase_characters_required = true
    is_numeric_characters_required   = true
    is_special_characters_required   = true
    minimum_password_length          = 14
    is_username_containment_allowed  = false
  }
}

# -- SC-28: KMS Vault and Master Key -----------------------------------------

resource "oci_kms_vault" "tenancy" {
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}-tenancy-vault"
  vault_type     = "DEFAULT"

  freeform_tags = local.common_tags
}

resource "oci_kms_key" "tenancy" {
  compartment_id      = var.compartment_id
  display_name        = "${var.name_prefix}-tenancy-master-key"
  protection_mode     = "HSM"
  management_endpoint = oci_kms_vault.tenancy.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }

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
  module_name    = "account-baseline/oci-tenancy"
  resource_id    = oci_logging_log_group.audit.id
  control_ids    = ["AU-2", "AC-3", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    audit_logging        = "enabled"
    password_min_length  = "14"
    encryption_algorithm = "AES-256"
    vault_type           = "DEFAULT"
  }
}
