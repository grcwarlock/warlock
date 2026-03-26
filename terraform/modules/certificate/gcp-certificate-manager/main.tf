###############################################################################
# GCP Certificate Manager Baseline
# Enforces: SC-17 (PKI Certificates), SC-23 (Session Authenticity)
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

# -- SC-17: Managed SSL certificate -------------------------------------------

resource "google_certificate_manager_certificate" "main" {
  name    = "${var.name_prefix}-cert"
  project = var.project_id
  labels  = local.common_labels

  managed {
    domains = var.domains
  }
}

# -- SC-23: Certificate map for load balancer binding --------------------------

resource "google_certificate_manager_certificate_map" "main" {
  name    = "${var.name_prefix}-cert-map"
  project = var.project_id
  labels  = local.common_labels
}

# -- SC-23: Map entry binding certificate to the map ---------------------------

resource "google_certificate_manager_certificate_map_entry" "main" {
  name         = "${var.name_prefix}-cert-map-entry"
  project      = var.project_id
  map          = google_certificate_manager_certificate_map.main.name
  certificates = [google_certificate_manager_certificate.main.id]
  hostname     = var.domains[0]
  labels       = local.common_labels
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "certificate/gcp-certificate-manager"
  resource_id    = google_certificate_manager_certificate.main.id
  control_ids    = ["SC-17", "SC-23"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    domains         = join(",", var.domains)
    certificate_map = google_certificate_manager_certificate_map.main.name
  }
}
