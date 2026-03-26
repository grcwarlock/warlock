###############################################################################
# GCP Drift Detection Baseline
# Enforces: CM-3 (Change Control), CM-8 (Component Inventory)
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

# -- Enable required APIs -----------------------------------------------------

resource "google_project_service" "cloud_asset" {
  project = var.project_id
  service = "cloudasset.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "cloud_scheduler" {
  project = var.project_id
  service = "cloudscheduler.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "cloudfunctions" {
  project = var.project_id
  service = "cloudfunctions.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "cloudbuild" {
  project = var.project_id
  service = "cloudbuild.googleapis.com"

  disable_on_destroy = false
}

# -- CM-8: GCS bucket for Cloud Function source code --------------------------

resource "google_storage_bucket" "function_source" {
  name                        = "${var.project_id}-${var.name_prefix}-drift-fn-src"
  location                    = var.region
  project                     = var.project_id
  uniform_bucket_level_access = true
  labels                      = local.common_labels

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 5
    }
    action {
      type = "Delete"
    }
  }
}

# -- CM-3: Cloud Function — compare Terraform state with Asset Inventory ------

resource "google_cloudfunctions2_function" "drift_checker" {
  name     = "${var.name_prefix}-drift-checker"
  location = var.region
  project  = var.project_id
  labels   = local.common_labels

  build_config {
    runtime     = "python312"
    entry_point = "check_drift"
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = "drift-checker.zip"
      }
    }
  }

  service_config {
    max_instance_count = 1
    available_memory   = "256M"
    timeout_seconds    = 300
    environment_variables = {
      STATE_BUCKET = var.state_bucket
      PROJECT_ID   = var.project_id
    }
  }

  depends_on = [
    google_project_service.cloudfunctions,
    google_project_service.cloudbuild,
    google_project_service.cloud_asset,
  ]
}

# -- CM-3: Cloud Scheduler job to trigger drift checks on a cron schedule ------

resource "google_cloud_scheduler_job" "drift_trigger" {
  name     = "${var.name_prefix}-drift-trigger"
  project  = var.project_id
  region   = var.region
  schedule = var.schedule

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.drift_checker.service_config[0].uri

    oidc_token {
      service_account_email = google_cloudfunctions2_function.drift_checker.service_config[0].service_account_email
    }
  }

  depends_on = [google_project_service.cloud_scheduler]
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "drift-detection/gcp-drift"
  resource_id    = google_cloudfunctions2_function.drift_checker.id
  control_ids    = ["CM-3", "CM-8"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    schedule     = var.schedule
    state_bucket = var.state_bucket
    region       = var.region
  }
}
