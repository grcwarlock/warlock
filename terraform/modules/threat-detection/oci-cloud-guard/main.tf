###############################################################################
# OCI Cloud Guard Baseline
# Enforces: SI-4 (System Monitoring), AU-6 (Audit Review / Analysis)
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

# -- SI-4: Enable Cloud Guard at tenancy level ---------------------------------

resource "oci_cloud_guard_cloud_guard_configuration" "main" {
  compartment_id   = var.tenancy_id
  reporting_region = var.reporting_region
  status           = "ENABLED"
}

# -- SI-4: Cloned Detector Recipe (from Oracle-managed) ------------------------

resource "oci_cloud_guard_detector_recipe" "main" {
  compartment_id            = var.compartment_id
  display_name              = "${var.name_prefix}-detector-recipe"
  source_detector_recipe_id = var.source_detector_recipe_id

  freeform_tags = local.common_tags

  depends_on = [oci_cloud_guard_cloud_guard_configuration.main]
}

# -- SI-4/AU-6: Cloud Guard Target --------------------------------------------

resource "oci_cloud_guard_target" "main" {
  compartment_id       = var.compartment_id
  display_name         = "${var.name_prefix}-target"
  target_resource_id   = var.compartment_id
  target_resource_type = "COMPARTMENT"

  target_detector_recipes {
    detector_recipe_id = oci_cloud_guard_detector_recipe.main.id
  }

  freeform_tags = local.common_tags

  depends_on = [oci_cloud_guard_cloud_guard_configuration.main]
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/oci-cloud-guard"
  resource_id    = oci_cloud_guard_target.main.id
  control_ids    = ["SI-4", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    status               = "ENABLED"
    target_resource_type = "COMPARTMENT"
    reporting_region     = var.reporting_region
  }
}
