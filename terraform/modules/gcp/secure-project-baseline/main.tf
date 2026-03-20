###############################################################################
# GCP Secure Project Baseline
# Enforces: AU-2 (Audit Logs), AC-3 (Org Policies), SC-28 (Encryption)
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    # T-4: Pin to compatible minor versions within the 5.x series
    google = { source = "hashicorp/google", version = "~> 5.0" }
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
  # T-7: Use name_prefix variable instead of hardcoded "grc_audit_logs"
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

# ── AC-3: Organization Policy Constraints (V2 API) ────────────────────
# T-12: Replaced deprecated google_project_organization_policy (V1) with
# google_org_policy_policy (V2 API). Key differences:
#   - Resource path format: "projects/{project_id}/policies/{constraint_short_name}"
#   - Constraint short name drops the "constraints/" prefix
#   - Boolean enforcement uses spec.rules[].enforce = true instead of boolean_policy block

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

# ── #41: Warlock self-registration evidence ───────────────────────────

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration evidence. Set to null to disable."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API authentication."
  type        = string
  default     = null
  sensitive   = true
}

resource "terraform_data" "warlock_evidence" {
  count = var.warlock_api_endpoint != null ? 1 : 0

  triggers_replace = [google_logging_project_sink.audit.id]

  provisioner "local-exec" {
    command = <<-EOT
      curl -sf -X POST "${var.warlock_api_endpoint}/api/v1/evidence" \
        -H "Authorization: Bearer ${var.warlock_api_token}" \
        -H "Content-Type: application/json" \
        -d '{
          "module": "gcp/secure-project-baseline",
          "resource_id": "${google_logging_project_sink.audit.id}",
          "control_ids": ["AU-2", "AC-3", "SC-28"],
          "attributes": {
            "project_id": "${var.project_id}",
            "region": "${var.region}",
            "log_retention_days": ${var.log_retention_days}
          }
        }' || true
    EOT
  }
}
