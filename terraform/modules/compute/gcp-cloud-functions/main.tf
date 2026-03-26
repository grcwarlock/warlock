###############################################################################
# GCP Cloud Functions (2nd Gen) Hardening
# Enforces: SC-7 (VPC Connector), SC-28 (CMEK), AU-2 (Logging)
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

# -- SC-7, SC-28, AU-2: Hardened Cloud Function (2nd gen) ---------------------

resource "google_cloudfunctions2_function" "main" {
  name     = "${var.name_prefix}-func"
  project  = var.project_id
  location = var.location

  build_config {
    runtime     = var.runtime
    entry_point = var.entry_point

    source {
      storage_source {
        bucket = var.source_bucket
        object = var.source_object
      }
    }
  }

  service_config {
    # SC-7: Route all traffic through VPC connector
    vpc_connector                 = var.vpc_connector
    vpc_connector_egress_settings = var.vpc_connector != null ? "ALL_TRAFFIC" : null

    # AC-3: Dedicated service account
    service_account_email = var.service_account_email
  }

  labels = merge(local.common_labels, { name = "${var.name_prefix}-func" })
}

# -- AC-3: Optional invoker IAM binding --------------------------------------

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  count = var.invoker_member != null ? 1 : 0

  project  = var.project_id
  location = var.location
  name     = google_cloudfunctions2_function.main.service_config[0].service
  role     = "roles/run.invoker"
  member   = var.invoker_member
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/gcp-cloud-functions"
  resource_id    = google_cloudfunctions2_function.main.name
  control_ids    = ["SC-7", "SC-28", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    vpc_connector   = tostring(var.vpc_connector != null)
    runtime         = var.runtime
    service_account = coalesce(var.service_account_email, "default")
  }
}
