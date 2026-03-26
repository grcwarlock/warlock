###############################################################################
# OCI Object Storage Baseline
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Enforcement)
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

# -- Namespace metadata --------------------------------------------------------

data "oci_objectstorage_namespace" "current" {
  compartment_id = var.compartment_id
}

# -- SC-28/AC-3: Secure Bucket ------------------------------------------------

resource "oci_objectstorage_bucket" "main" {
  compartment_id = var.compartment_id
  namespace      = var.namespace
  name           = "${var.name_prefix}-bucket"
  access_type    = "NoPublicAccess"
  versioning     = "Enabled"
  auto_tiering   = "InfrequentAccess"
  kms_key_id     = var.kms_key_id

  freeform_tags = local.common_tags
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/oci-object-storage"
  resource_id    = oci_objectstorage_bucket.main.bucket_id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    access_type  = "NoPublicAccess"
    versioning   = "Enabled"
    auto_tiering = "InfrequentAccess"
    encrypted    = tostring(var.kms_key_id != null)
  }
}
