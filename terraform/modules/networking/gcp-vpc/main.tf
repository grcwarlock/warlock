###############################################################################
# GCP VPC with Firewall Hardening
# Enforces: SC-7 (Boundary Protection), AU-2 (Flow Logs)
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

# -- SC-7: VPC Network (custom mode) -----------------------------------------

resource "google_compute_network" "main" {
  name                    = "${var.name_prefix}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# -- SC-7: Subnet with private Google access and flow logs --------------------

resource "google_compute_subnetwork" "main" {
  name                     = "${var.name_prefix}-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.main.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
}

# -- SC-7: Deny all ingress by default ---------------------------------------

resource "google_compute_firewall" "deny_all_ingress" {
  name    = "${var.name_prefix}-deny-all-ingress"
  project = var.project_id
  network = google_compute_network.main.id

  priority  = 65534
  direction = "INGRESS"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# -- SC-7: Allow internal traffic within VPC ----------------------------------

resource "google_compute_firewall" "allow_internal" {
  name    = "${var.name_prefix}-allow-internal"
  project = var.project_id
  network = google_compute_network.main.id

  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.subnet_cidr]
}

# -- SC-7: Allow GCP health check ranges -------------------------------------

resource "google_compute_firewall" "allow_health_checks" {
  name    = "${var.name_prefix}-allow-health-checks"
  project = var.project_id
  network = google_compute_network.main.id

  priority  = 1100
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }

  # Google health check IP ranges
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
}

# -- SC-7: Cloud Router (optional, for NAT) -----------------------------------

resource "google_compute_router" "main" {
  count = var.enable_cloud_nat ? 1 : 0

  name    = "${var.name_prefix}-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.main.id
}

# -- SC-7: Cloud NAT (optional) -----------------------------------------------

resource "google_compute_router_nat" "main" {
  count = var.enable_cloud_nat ? 1 : 0

  name                               = "${var.name_prefix}-nat"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.main[0].name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/gcp-vpc"
  resource_id    = google_compute_network.main.id
  control_ids    = ["SC-7", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    subnet_cidr      = var.subnet_cidr
    enable_flow_logs = tostring(var.enable_flow_logs)
    enable_cloud_nat = tostring(var.enable_cloud_nat)
    deny_all_ingress = "true"
  }
}
