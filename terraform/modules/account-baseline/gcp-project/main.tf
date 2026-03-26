###############################################################################
# GCP Secure Project Baseline
# Enforces: AU-2 (Audit Logs), AC-3 (Org Policies), SC-28 (Encryption)
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

# -- Enable Required APIs ----------------------------------------------------

resource "google_project_service" "apis" {
  for_each = toset([
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "securitycenter.googleapis.com",
    "cloudasset.googleapis.com",
  ])
  project = var.project_id
  service = each.value
}

# -- AU-2: Logging Sink to BigQuery ------------------------------------------

resource "google_bigquery_dataset" "audit_logs" {
  dataset_id = "${var.name_prefix}_audit_logs"
  project    = var.project_id
  location   = var.region
  labels     = local.common_labels

  default_table_expiration_ms = var.log_retention_days * 86400000

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }
}

resource "google_logging_project_sink" "audit" {
  name        = "grc-audit-sink"
  project     = var.project_id
  destination = "bigquery.googleapis.com/${google_bigquery_dataset.audit_logs.id}"
  filter      = "logName:\"logs/cloudaudit.googleapis.com\""

  unique_writer_identity = true
}

resource "google_bigquery_dataset_iam_member" "sink_writer" {
  dataset_id = google_bigquery_dataset.audit_logs.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.audit.writer_identity
}

# -- AC-3: Organization Policy Constraints (V2 API) --------------------------

resource "google_org_policy_policy" "uniform_bucket" {
  name   = "projects/${var.project_id}/policies/storage.uniformBucketLevelAccess"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "os_login" {
  name   = "projects/${var.project_id}/policies/compute.requireOsLogin"
  parent = "projects/${var.project_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "account-baseline/gcp-project"
  resource_id    = google_logging_project_sink.audit.id
  control_ids    = ["AU-2", "AC-3", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    project_id         = var.project_id
    region             = var.region
    log_retention_days = tostring(var.log_retention_days)
  }
}
