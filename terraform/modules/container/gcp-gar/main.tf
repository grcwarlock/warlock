###############################################################################
# Google Artifact Registry Hardening Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Management)
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

# -- SC-28/CM-6: Artifact Registry Docker repository --------------------------

resource "google_artifact_registry_repository" "main" {
  location      = var.location
  repository_id = "${var.name_prefix}-docker"
  project       = var.project_id
  format        = "DOCKER"
  mode          = "STANDARD_REPOSITORY"
  description   = "Warlock-managed Docker repository with CMEK and access controls"
  kms_key_name  = var.kms_key_name # SC-28: CMEK encryption (null = Google-managed)
  labels        = local.common_labels
}

# -- CM-6: IAM reader bindings (optional) --------------------------------------

resource "google_artifact_registry_repository_iam_member" "readers" {
  for_each   = toset(var.reader_members)
  project    = var.project_id
  location   = var.location
  repository = google_artifact_registry_repository.main.name
  role       = "roles/artifactregistry.reader"
  member     = each.value
}

# -- CM-6: IAM writer bindings (optional) --------------------------------------

resource "google_artifact_registry_repository_iam_member" "writers" {
  for_each   = toset(var.writer_members)
  project    = var.project_id
  location   = var.location
  repository = google_artifact_registry_repository.main.name
  role       = "roles/artifactregistry.writer"
  member     = each.value
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "container/gcp-gar"
  resource_id    = google_artifact_registry_repository.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    format       = "DOCKER"
    mode         = "STANDARD_REPOSITORY"
    cmek_enabled = tostring(var.kms_key_name != null)
    location     = var.location
  }
}
