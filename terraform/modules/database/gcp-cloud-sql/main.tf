###############################################################################
# GCP Cloud SQL Hardening
# Enforces: SC-28 (Encryption at Rest), AU-2 (Audit Logging), SC-7 (Network)
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

# -- SC-28/AU-2/SC-7: Cloud SQL instance with private IP, backups, pgaudit ----

resource "google_sql_database_instance" "main" {
  name             = "${var.name_prefix}-sql"
  database_version = var.database_version
  region           = var.region
  project          = var.project_id

  deletion_protection = true

  settings {
    tier = var.tier

    user_labels = local.common_labels

    ip_configuration {
      ipv4_enabled    = false               # SC-7: no public IP
      private_network = var.private_network # SC-7: VPC-only access
    }

    backup_configuration {
      enabled                        = true # AU-2: automated backups
      point_in_time_recovery_enabled = true
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on" # AU-2: audit logging
    }

    database_flags {
      name  = "log_connections"
      value = "on" # AU-2: audit logging
    }

    database_flags {
      name  = "log_disconnections"
      value = "on" # AU-2: audit logging
    }
  }
}

# -- SC-28: Database -----------------------------------------------------------

resource "google_sql_database" "main" {
  name     = "${var.name_prefix}-db"
  instance = google_sql_database_instance.main.name
  project  = var.project_id
}

# -- AC-3: Database user -------------------------------------------------------

resource "google_sql_user" "main" {
  name     = "${var.name_prefix}-user"
  instance = google_sql_database_instance.main.name
  project  = var.project_id
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "database/gcp-cloud-sql"
  resource_id    = google_sql_database_instance.main.id
  control_ids    = ["SC-28", "AU-2", "SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    ipv4_enabled           = "false"
    backup_enabled         = "true"
    point_in_time_recovery = "true"
    deletion_protection    = "true"
    audit_logging          = "true"
  }
}
