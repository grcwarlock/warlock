###############################################################################
# OCI Audit Logging Baseline
# Enforces: AU-2 (Event Logging), AU-6 (Audit Review / Analysis)
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

# -- AU-2: Log Group -----------------------------------------------------------

resource "oci_logging_log_group" "audit" {
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}-audit-log-group"
  description    = "Warlock-managed audit log group for compliance logging"

  freeform_tags = local.common_tags
}

# -- AU-2: Service Log (Audit Events) -----------------------------------------

resource "oci_logging_log" "audit" {
  display_name = "${var.name_prefix}-audit-log"
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

# -- AU-6: Audit Archive Bucket ------------------------------------------------

resource "oci_objectstorage_bucket" "audit_archive" {
  compartment_id = var.compartment_id
  namespace      = var.namespace
  name           = "${var.name_prefix}-audit-archive"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"

  freeform_tags = local.common_tags
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/oci-audit"
  resource_id    = oci_logging_log_group.audit.id
  control_ids    = ["AU-2", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    log_type   = "SERVICE"
    service    = "audit"
    archive    = oci_objectstorage_bucket.audit_archive.name
    tenancy_id = var.tenancy_id
  }
}
