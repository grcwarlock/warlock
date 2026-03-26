###############################################################################
# OCI Compute Instance Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Settings)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    oci = { source = "oracle/oci", version = "~> 5.0" }
  }
}

locals {
  common_tags = merge(var.tags, { managed_by = "warlock" })
}

# -- SC-28/CM-6: Compute Instance ---------------------------------------------

resource "oci_core_instance" "main" {
  compartment_id      = var.compartment_id
  availability_domain = var.availability_domain
  display_name        = "${var.name_prefix}-instance"
  shape               = var.shape

  shape_config {
    ocpus         = var.ocpus
    memory_in_gbs = var.memory_in_gbs
  }

  source_details {
    source_type             = "image"
    source_id               = var.image_id
    boot_volume_size_in_gbs = var.boot_volume_size_gbs
  }

  create_vnic_details {
    subnet_id        = var.subnet_id
    assign_public_ip = false
    display_name     = "${var.name_prefix}-vnic"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
  }

  launch_options {
    network_type = "PARAVIRTUALIZED"
  }

  is_pv_encryption_in_transit_enabled = true

  freeform_tags = local.common_tags
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/oci-compute"
  resource_id    = oci_core_instance.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    shape                   = var.shape
    encryption_in_transit   = "true"
    paravirtualized_network = "true"
    public_ip               = "false"
  }
}
