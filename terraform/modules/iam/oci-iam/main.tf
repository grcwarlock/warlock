###############################################################################
# OCI IAM Baseline
# Enforces: AC-2 (Account Management), AC-6 (Least Privilege)
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

# -- AC-2: Isolation Compartment -----------------------------------------------

resource "oci_identity_compartment" "workload" {
  compartment_id = var.compartment_id
  name           = "${var.name_prefix}-workload"
  description    = "Warlock-managed isolation compartment for workload resources"
  enable_delete  = false

  freeform_tags = local.common_tags
}

# -- AC-6: Auditor Group (read-only) ------------------------------------------

resource "oci_identity_group" "auditors" {
  compartment_id = var.tenancy_id
  name           = var.auditor_group_name
  description    = "Warlock-managed auditor group with read-only access"

  freeform_tags = local.common_tags
}

# -- AC-6: Read-Only Policy for Auditors --------------------------------------

resource "oci_identity_policy" "auditor_readonly" {
  compartment_id = var.tenancy_id
  name           = "${var.name_prefix}-auditor-readonly"
  description    = "Read-only access for auditor group (AC-6 least privilege)"
  statements = [
    "Allow group ${oci_identity_group.auditors.name} to inspect all-resources in compartment ${oci_identity_compartment.workload.name}",
    "Allow group ${oci_identity_group.auditors.name} to read audit-events in compartment ${oci_identity_compartment.workload.name}",
    "Allow group ${oci_identity_group.auditors.name} to read log-groups in compartment ${oci_identity_compartment.workload.name}",
    "Allow group ${oci_identity_group.auditors.name} to read log-content in compartment ${oci_identity_compartment.workload.name}",
  ]

  freeform_tags = local.common_tags
}

# -- AC-2: Authentication Policy (password complexity) -------------------------

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

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/oci-iam"
  resource_id    = oci_identity_compartment.workload.id
  control_ids    = ["AC-2", "AC-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    compartment_name    = oci_identity_compartment.workload.name
    auditor_group       = oci_identity_group.auditors.name
    min_password_length = "14"
  }
}
