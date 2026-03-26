###############################################################################
# OVH Object Storage (OpenStack Swift) — LIMITED
# Enforces: SC-28 (Encryption at Rest), AC-3 (Access Control)
#
# OVH Object Storage is backed by OpenStack Swift. User-managed encryption
# keys are not available via Terraform. See remediation.tf for limitations.
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    openstack = { source = "terraform-provider-openstack/openstack", version = "~> 1.54" }
  }
}

# -- SC-28, AC-3: Private object storage container ----------------------------

resource "openstack_objectstorage_container_v1" "main" {
  name = "${var.name_prefix}-object-storage"

  metadata = {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  }

  # AC-3: Container read/write ACLs left empty = project-only access
  container_read  = var.container_read_acl
  container_write = var.container_write_acl

  versioning_legacy {
    type     = "versions"
    location = "${var.name_prefix}-object-storage-versions"
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "storage/ovh-object-storage"
  resource_id    = openstack_objectstorage_container_v1.main.name
  control_ids    = ["SC-28", "AC-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    versioning_enabled = "true"
    provider_note      = "OVH uses OpenStack Swift. Server-side encryption is platform-managed."
  }
}
