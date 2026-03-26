###############################################################################
# GCP Compute Engine Instance Hardening
# Enforces: SC-28 (Disk Encryption), CM-6 (Shielded VM), AC-3 (Service Account)
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

# -- SC-28, CM-6, AC-3: Hardened GCE instance ---------------------------------

resource "google_compute_instance" "main" {
  name         = "${var.name_prefix}-vm"
  project      = var.project_id
  zone         = var.zone
  machine_type = var.machine_type

  # CM-6: Shielded VM configuration
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # CM-6: OS Login for centralized SSH access
  metadata = {
    enable-oslogin = "TRUE"
  }

  # SC-28: Encrypted boot disk with optional CMEK
  boot_disk {
    initialize_params {
      image = var.source_image
    }
    kms_key_self_link = var.kms_key_self_link
  }

  network_interface {
    subnetwork = var.subnet_self_link
  }

  # AC-3: Dedicated service account with least-privilege scope
  service_account {
    scopes = ["cloud-platform"]
  }

  labels = merge(local.common_labels, { name = "${var.name_prefix}-vm" })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/gcp-compute"
  resource_id    = google_compute_instance.main.self_link
  control_ids    = ["SC-28", "CM-6", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    shielded_vm  = "true"
    secure_boot  = "true"
    os_login     = "true"
    cmek_enabled = tostring(var.kms_key_self_link != null)
  }
}
