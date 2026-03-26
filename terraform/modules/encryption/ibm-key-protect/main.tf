###############################################################################
# IBM Cloud Key Protect Baseline
# Enforces: SC-12 (Cryptographic Key Management), SC-28 (Encryption at Rest)
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

# -- SC-12: Key Protect Instance -----------------------------------------------

resource "ibm_resource_instance" "key_protect" {
  name              = "${var.name_prefix}-key-protect"
  service           = "kms"
  plan              = "tiered-pricing"
  location          = var.region
  resource_group_id = var.resource_group_id
  tags              = local.common_tags
}

# -- SC-12/SC-28: Root Key (non-extractable, no force delete) -----------------

resource "ibm_kms_key" "root" {
  instance_id  = ibm_resource_instance.key_protect.guid
  key_name     = "${var.name_prefix}-root-key"
  standard_key = false
  force_delete = false
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "encryption/ibm-key-protect"
  resource_id    = ibm_kms_key.root.key_id
  control_ids    = ["SC-12", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    standard_key = "false"
    force_delete = "false"
    region       = var.region
  }
}
