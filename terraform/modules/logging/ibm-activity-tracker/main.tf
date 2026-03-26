###############################################################################
# IBM Cloud Activity Tracker Baseline
# Enforces: AU-2 (Event Logging), AU-6 (Audit Review / Analysis)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    ibm = { source = "IBM-Cloud/ibm", version = "~> 1.60" }
  }
}

locals {
  common_tags = concat(var.tags, ["managed-by:warlock"])
}

# -- AU-2: Activity Tracker Instance -------------------------------------------

resource "ibm_resource_instance" "activity_tracker" {
  name              = "${var.name_prefix}-activity-tracker"
  service           = "logdnaat"
  plan              = "7-day"
  location          = var.region
  resource_group_id = var.resource_group_id
  tags              = local.common_tags
}

# -- AU-6: Activity Tracker Target (COS archive) ------------------------------

resource "ibm_atracker_target" "cos" {
  name        = "${var.name_prefix}-atracker-cos-target"
  target_type = "cloud_object_storage"

  cos_endpoint {
    endpoint   = "s3.private.${var.region}.cloud-object-storage.appdomain.cloud"
    bucket     = var.cos_bucket_name
    target_crn = var.cos_bucket_crn
  }
}

# -- AU-6: Activity Tracker Route ---------------------------------------------

resource "ibm_atracker_route" "main" {
  name = "${var.name_prefix}-atracker-route"

  rules {
    target_ids = [ibm_atracker_target.cos.id]
    locations  = [var.region, "global"]
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "logging/ibm-activity-tracker"
  resource_id    = ibm_resource_instance.activity_tracker.id
  control_ids    = ["AU-2", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    target_type = "cloud_object_storage"
    region      = var.region
  }
}
