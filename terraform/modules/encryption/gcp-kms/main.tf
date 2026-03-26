###############################################################################
# GCP Cloud KMS Baseline
# Enforces: SC-12 (Cryptographic Key Management), SC-28 (Encryption at Rest)
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

# -- Enable KMS API -----------------------------------------------------------

resource "google_project_service" "kms" {
  project = var.project_id
  service = "cloudkms.googleapis.com"

  disable_on_destroy = false
}

# -- SC-12: Cloud KMS Keyring -------------------------------------------------

resource "google_kms_key_ring" "main" {
  name     = "${var.name_prefix}-keyring"
  location = var.location
  project  = var.project_id

  depends_on = [google_project_service.kms]
}

# -- SC-12/SC-28: Crypto Key with rotation ------------------------------------

resource "google_kms_crypto_key" "main" {
  name            = "${var.name_prefix}-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = var.rotation_period # SC-12: automatic rotation
  purpose         = var.key_purpose

  lifecycle {
    prevent_destroy = true
  }

  labels = local.common_labels
}

# -- SC-28: CMEK for GCS ------------------------------------------------------

resource "google_storage_bucket" "cmek_example" {
  count    = var.create_cmek_bucket ? 1 : 0
  name     = "${var.project_id}-${var.name_prefix}-cmek"
  location = var.location
  project  = var.project_id
  labels   = local.common_labels

  uniform_bucket_level_access = true

  encryption {
    default_kms_key_name = google_kms_crypto_key.main.id
  }

  versioning {
    enabled = true
  }
}

# Grant GCS service account permission to use the CMEK key
resource "google_kms_crypto_key_iam_member" "gcs_cmek" {
  count         = var.create_cmek_bucket ? 1 : 0
  crypto_key_id = google_kms_crypto_key.main.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${var.project_number}@gs-project-accounts.iam.gserviceaccount.com"
}

# -- SC-12: IAM bindings on the key -------------------------------------------

resource "google_kms_key_ring_iam_member" "admins" {
  for_each    = toset(var.key_admin_members)
  key_ring_id = google_kms_key_ring.main.id
  role        = "roles/cloudkms.admin"
  member      = each.value
}

resource "google_kms_crypto_key_iam_member" "encrypter_decrypters" {
  for_each      = toset(var.encrypter_decrypter_members)
  crypto_key_id = google_kms_crypto_key.main.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/gcp-kms"
  resource_id    = google_kms_crypto_key.main.id
  control_ids    = ["SC-12", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    rotation_period = var.rotation_period
    key_purpose     = var.key_purpose
    location        = var.location
  }
}
