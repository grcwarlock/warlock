###############################################################################
# OCI Container Registry Baseline
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

# -- SC-28/CM-6: Immutable Private Container Repository -----------------------

resource "oci_artifacts_container_repository" "main" {
  compartment_id = var.compartment_id
  display_name   = "${var.name_prefix}-repo"
  is_immutable   = true
  is_public      = false
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "container/oci-container-registry"
  resource_id    = oci_artifacts_container_repository.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    is_immutable = "true"
    is_public    = "false"
  }
}
