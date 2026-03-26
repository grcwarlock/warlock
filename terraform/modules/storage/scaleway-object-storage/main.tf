###############################################################################
# Scaleway Object Storage
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    scaleway = { source = "scaleway/scaleway", version = "~> 2.30" }
  }
}

# -- SC-28, AC-3: Private bucket with versioning ------------------------------

resource "scaleway_object_bucket" "main" {
  name   = "${var.name_prefix}-bucket"
  region = var.region
  acl    = var.acl
  tags   = merge({ ManagedBy = "warlock", Framework = "NIST-800-53" }, { for t in var.tags : split(":", t)[0] => split(":", t)[1] if length(split(":", t)) == 2 })

  versioning {
    enabled = true
  }
}

# -- SC-28: Optional object lock configuration --------------------------------

resource "scaleway_object_bucket_lock_configuration" "main" {
  count = var.enable_object_lock ? 1 : 0

  bucket = scaleway_object_bucket.main.name
  region = var.region

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/scaleway-object-storage"
  resource_id    = scaleway_object_bucket.main.id
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    acl                = var.acl
    versioning_enabled = "true"
    object_lock        = tostring(var.enable_object_lock)
    region             = var.region
  }
}
