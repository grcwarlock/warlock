###############################################################################
# Warlock Connector Provisioning — GCP
# Provisions service account, workload identity federation, and Secret Manager
# secrets for Warlock connector access to GCP projects.
# Enforces: AC-2 (Account Management), AC-3 (Access Enforcement),
#           SC-12 (Cryptographic Key Management), IA-2 (Identification)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  common_labels = merge(var.labels, {
    managed_by = "warlock"
    component  = "connector-provisioning"
  })
  sa_account_id = "${var.name_prefix}-connector"
}

# -- Service Account for Warlock connector ------------------------------------

resource "google_service_account" "warlock_connector" {
  project      = var.project_id
  account_id   = local.sa_account_id
  display_name = "Warlock GRC Connector"
  description  = "Service account for Warlock connector with Security Reviewer access"
}

# Security Reviewer role on the project
resource "google_project_iam_member" "security_reviewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${google_service_account.warlock_connector.email}"
}

# Security Center findings viewer for threat detection connectors
resource "google_project_iam_member" "scc_viewer" {
  project = var.project_id
  role    = "roles/securitycenter.findingsViewer"
  member  = "serviceAccount:${google_service_account.warlock_connector.email}"
}

# -- Workload Identity Federation (keyless auth) ------------------------------

resource "google_iam_workload_identity_pool" "warlock" {
  count = var.create_workload_identity_pool ? 1 : 0

  project                   = var.project_id
  workload_identity_pool_id = "${var.name_prefix}-warlock-pool"
  display_name              = "Warlock GRC Platform"
  description               = "Workload identity pool for keyless Warlock connector authentication"
}

resource "google_iam_workload_identity_pool_provider" "warlock_aws" {
  count = var.create_workload_identity_pool && var.warlock_aws_account_id != null ? 1 : 0

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.warlock[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "${var.name_prefix}-warlock-aws"
  display_name                       = "Warlock Platform (AWS)"
  description                        = "Allows Warlock running in AWS to authenticate via workload identity"

  aws {
    account_id = var.warlock_aws_account_id
  }

  attribute_mapping = {
    "google.subject"        = "assertion.arn"
    "attribute.aws_account" = "assertion.account"
  }
}

resource "google_iam_workload_identity_pool_provider" "warlock_oidc" {
  count = var.create_workload_identity_pool && var.warlock_oidc_issuer != null ? 1 : 0

  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.warlock[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "${var.name_prefix}-warlock-oidc"
  display_name                       = "Warlock Platform (OIDC)"
  description                        = "Allows Warlock to authenticate via OIDC identity provider"

  oidc {
    issuer_uri = var.warlock_oidc_issuer
  }

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
}

# Allow the workload identity pool to impersonate the service account
resource "google_service_account_iam_member" "workload_identity_binding" {
  count = var.create_workload_identity_pool ? 1 : 0

  service_account_id = google_service_account.warlock_connector.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.warlock[0].name}/*"
}

# -- Secret Manager for API tokens -------------------------------------------

resource "google_secret_manager_secret" "connector_tokens" {
  for_each = toset(var.connector_names)

  project   = var.project_id
  secret_id = "${var.name_prefix}-connector-${each.value}"

  labels = local.common_labels

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "connector_tokens" {
  for_each = toset(var.connector_names)

  secret      = google_secret_manager_secret.connector_tokens[each.value].id
  secret_data = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

# Allow the Warlock SA to access secrets
resource "google_secret_manager_secret_iam_member" "connector_accessor" {
  for_each = toset(var.connector_names)

  project   = var.project_id
  secret_id = google_secret_manager_secret.connector_tokens[each.value].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.warlock_connector.email}"
}

# -- Warlock self-registration ------------------------------------------------

