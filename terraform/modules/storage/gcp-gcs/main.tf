###############################################################################
# GCP Cloud Storage Bucket Hardening
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

locals {
  common_labels = merge(var.labels, { managed_by = "warlock" })
}

# -- SC-28/AC-3: GCS bucket with uniform access and versioning ----------------

resource "google_storage_bucket" "main" {
  name     = "${var.name_prefix}-${var.project_id}"
  location = var.location
  project  = var.project_id
  labels   = local.common_labels

  uniform_bucket_level_access = true # AC-3: uniform IAM-only access

  versioning {
    enabled = true # SC-28: object versioning
  }

  dynamic "encryption" {
    for_each = var.kms_key_name != null ? [1] : []
    content {
      default_kms_key_name = var.kms_key_name # SC-28: CMEK encryption
    }
  }

  public_access_prevention = "enforced" # AC-3: prevent public access
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/gcp-gcs"
  resource_id    = google_storage_bucket.main.id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    uniform_bucket_level_access = "true"
    versioning_enabled          = "true"
    public_access_prevention    = "enforced"
    cmek_enabled                = tostring(var.kms_key_name != null)
  }
}
