###############################################################################
# GCP Secure Project Baseline
# Enforces: AU-2 (Audit Logs), AC-3 (Org Policies), SC-28 (Encryption)
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

locals {
  common_labels = merge(var.labels, { managed_by = "warlock" })
}

# ── Enable Required APIs ─────────────────────────────────────────────

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

# ── AU-2: Logging Sink to BigQuery ───────────────────────────────────

resource "google_bigquery_dataset" "audit_logs" {
  dataset_id = "grc_audit_logs"
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

# ── AC-3: Organization Policy Constraints ────────────────────────────

resource "google_project_organization_policy" "uniform_bucket" {
  project    = var.project_id
  constraint = "constraints/storage.uniformBucketLevelAccess"
  boolean_policy { enforced = true }
}

resource "google_project_organization_policy" "os_login" {
  project    = var.project_id
  constraint = "constraints/compute.requireOsLogin"
  boolean_policy { enforced = true }
}
