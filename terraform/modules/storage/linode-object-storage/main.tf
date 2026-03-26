###############################################################################
# Linode Object Storage Bucket + Access Key
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    linode = { source = "linode/linode", version = "~> 2.12" }
  }
}

# -- SC-28/AC-3: Object storage bucket with private ACL ----------------------

resource "linode_object_storage_bucket" "main" {
  label   = var.label
  cluster = var.cluster
  acl     = var.acl
}

# -- AC-3: Optional access key for programmatic access ------------------------

resource "linode_object_storage_key" "main" {
  count = var.create_access_key ? 1 : 0
  label = "${var.name_prefix}-obj-key"

  bucket_access {
    bucket_name = linode_object_storage_bucket.main.label
    cluster     = var.cluster
    permissions = "read_write"
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/linode-object-storage"
  resource_id    = "${var.cluster}/${linode_object_storage_bucket.main.label}"
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    acl        = var.acl
    cluster    = var.cluster
    access_key = tostring(var.create_access_key)
  }
}
