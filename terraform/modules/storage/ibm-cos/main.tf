###############################################################################
# IBM Cloud Object Storage Baseline
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Enforcement)
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

# -- SC-28: Cloud Object Storage Instance --------------------------------------

resource "ibm_resource_instance" "cos" {
  name              = "${var.name_prefix}-cos"
  service           = "cloud-object-storage"
  plan              = "standard"
  location          = "global"
  resource_group_id = var.resource_group_id
  tags              = local.common_tags
}

# -- SC-28/AC-3: Secure COS Bucket --------------------------------------------

resource "ibm_cos_bucket" "main" {
  bucket_name          = "${var.name_prefix}-bucket-${var.region}"
  resource_instance_id = ibm_resource_instance.cos.id
  region_location      = var.region
  storage_class        = "smart"
  key_protect          = var.kms_key_crn

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
  module_name    = "storage/ibm-cos"
  resource_id    = ibm_cos_bucket.main.id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    storage_class     = "smart"
    versioning        = "true"
    activity_tracking = "true"
    metrics           = "true"
    encrypted         = tostring(var.kms_key_crn != null)
  }
}
