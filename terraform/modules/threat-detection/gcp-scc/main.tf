###############################################################################
# GCP Security Command Center Baseline
# Enforces: SI-4 (System Monitoring), AU-6 (Audit Review)
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

# -- SI-4: Pub/Sub topic for SCC finding notifications ------------------------

resource "google_pubsub_topic" "scc_findings" {
  name    = "${var.name_prefix}-scc-findings"
  project = var.project_id
  labels  = local.common_labels
}

# -- SI-4/AU-6: SCC notification config — stream findings to Pub/Sub ----------

resource "google_scc_notification_config" "main" {
  config_id    = "${var.name_prefix}-scc-notify"
  organization = var.organization_id
  description  = "Stream active SCC findings to Pub/Sub for Warlock ingestion"
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = var.notification_filter
  }
}

# -- SI-4: Custom SCC source (optional) ---------------------------------------

resource "google_scc_source" "warlock" {
  count        = var.create_custom_source ? 1 : 0
  display_name = "${var.name_prefix}-warlock"
  organization = var.organization_id
  description  = "Custom source for Warlock GRC platform findings"
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/gcp-scc"
  resource_id    = google_scc_notification_config.main.name
  control_ids    = ["SI-4", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    notification_filter = var.notification_filter
    pubsub_topic        = google_pubsub_topic.scc_findings.id
  }
}
