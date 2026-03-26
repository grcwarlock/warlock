###############################################################################
# GCP Secret Manager
# Enforces: SC-12 (Key Management), IA-5 (Authenticator Management)
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

# -- Enable Secret Manager API ------------------------------------------------

resource "google_project_service" "secretmanager" {
  project = var.project_id
  service = "secretmanager.googleapis.com"

  disable_on_destroy = false
}

# -- SC-12/IA-5: Secret with replication and optional CMEK ---------------------

resource "google_secret_manager_secret" "main" {
  secret_id = var.secret_id
  project   = var.project_id
  labels    = local.common_labels

  replication {
    dynamic "user_managed" {
      for_each = length(var.replication_locations) > 0 ? [1] : []
      content {
        dynamic "replicas" {
          for_each = var.replication_locations
          content {
            location = replicas.value
            dynamic "customer_managed_encryption" {
              for_each = var.kms_key_name != null ? [1] : []
              content {
                kms_key_name = var.kms_key_name # SC-12: CMEK encryption
              }
            }
          }
        }
      }
    }
    dynamic "auto" {
      for_each = length(var.replication_locations) == 0 ? [1] : []
      content {}
    }
  }

  depends_on = [google_project_service.secretmanager]
}

# -- IA-5: Secret version (the actual secret data) ----------------------------

resource "google_secret_manager_secret_version" "main" {
  secret      = google_secret_manager_secret.main.id
  secret_data = var.secret_data
}

# -- AC-3: IAM bindings for secret accessors (optional) -----------------------

resource "google_secret_manager_secret_iam_member" "accessors" {
  for_each  = toset(var.accessor_members)
  secret_id = google_secret_manager_secret.main.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = each.value
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "secrets/gcp-secret-manager"
  resource_id    = google_secret_manager_secret.main.id
  control_ids    = ["SC-12", "IA-5"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    replication_type = length(var.replication_locations) > 0 ? "user_managed" : "auto"
    cmek_enabled     = tostring(var.kms_key_name != null)
    accessor_count   = tostring(length(var.accessor_members))
  }
}
