###############################################################################
# IBM Cloud Account Baseline (Composite)
# Enforces: AU-2 (Activity Tracker), AC-6 (IAM Settings),
#           SC-28 (COS Encryption)
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

# -- AU-2: Activity Tracker with COS Archive ----------------------------------

resource "ibm_resource_instance" "activity_tracker" {
  name              = "${var.name_prefix}-account-atracker"
  service           = "logdnaat"
  plan              = "7-day"
  location          = var.region
  resource_group_id = var.resource_group_id
  tags              = local.common_tags
}

resource "ibm_atracker_target" "cos" {
  name        = "${var.name_prefix}-account-atracker-target"
  target_type = "cloud_object_storage"

  cos_endpoint {
    endpoint   = "s3.private.${var.region}.cloud-object-storage.appdomain.cloud"
    bucket     = var.cos_bucket_name
    target_crn = var.cos_bucket_crn
  }
}

resource "ibm_atracker_route" "main" {
  name = "${var.name_prefix}-account-atracker-route"

  rules {
    target_ids = [ibm_atracker_target.cos.id]
    locations  = [var.region, "global"]
  }
}

# -- AC-6: IAM Account Settings (MFA, session, restrictions) ------------------

resource "ibm_iam_account_settings" "strict" {
  mfa                             = "LEVEL3"
  restrict_create_service_id      = "RESTRICTED"
  restrict_create_platform_apikey = "RESTRICTED"
  session_expiration_in_seconds   = "3600"
  session_invalidation_in_seconds = "900"
}

# -- SC-28: COS Instance with Encryption for Account Data ---------------------

resource "ibm_resource_instance" "cos" {
  name              = "${var.name_prefix}-account-cos"
  service           = "cloud-object-storage"
  plan              = "standard"
  location          = "global"
  resource_group_id = var.resource_group_id
  tags              = local.common_tags
}

resource "ibm_cos_bucket" "account_data" {
  bucket_name          = "${var.name_prefix}-account-data-${var.region}"
  resource_instance_id = ibm_resource_instance.cos.id
  region_location      = var.region
  storage_class        = "smart"

  activity_tracking {
    read_data_events  = true
    write_data_events = true
  }

  metrics_monitoring {
    usage_metrics_enabled   = true
    request_metrics_enabled = true
  }

  object_versioning {
    enable = true
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "account-baseline/ibm-account"
  resource_id    = ibm_resource_instance.activity_tracker.id
  control_ids    = ["AU-2", "AC-6", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    activity_tracker = "enabled"
    mfa_level        = "LEVEL3"
    cos_versioning   = "true"
    region           = var.region
  }
}
