###############################################################################
# GCP Cloud Audit Logs + BigQuery Sink
# Enforces: AU-2 (Event Logging), AU-6 (Audit Review)
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

# -- AU-2: Enable audit logging for all services -----------------------------

resource "google_project_iam_audit_config" "all_services" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# -- AU-6: BigQuery dataset for audit log storage ----------------------------

resource "google_bigquery_dataset" "audit_logs" {
  dataset_id    = "${replace(var.name_prefix, "-", "_")}_audit_logs"
  friendly_name = "${var.name_prefix} Audit Logs"
  description   = "BigQuery dataset for GCP audit log storage (AU-6)"
  project       = var.project_id
  location      = var.region

  default_table_expiration_ms = var.log_retention_days * 86400000 # days -> ms

  labels = local.common_labels
}

# -- AU-6: Log sink to BigQuery -----------------------------------------------

resource "google_logging_project_sink" "audit_sink" {
  name                   = "${var.name_prefix}-audit-sink"
  project                = var.project_id
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.audit_logs.dataset_id}"
  filter                 = "logName:\"cloudaudit.googleapis.com\""
  unique_writer_identity = true
}

# Grant the sink writer identity access to the BigQuery dataset
resource "google_bigquery_dataset_iam_member" "sink_writer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.audit_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.audit_sink.writer_identity
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/gcp-audit-log"
  resource_id    = google_logging_project_sink.audit_sink.id
  control_ids    = ["AU-2", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    log_retention_days = tostring(var.log_retention_days)
    audit_log_types    = "ADMIN_READ,DATA_READ,DATA_WRITE"
    sink_destination   = "bigquery"
  }
}
