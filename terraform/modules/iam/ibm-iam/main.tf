###############################################################################
# IBM Cloud IAM Baseline
# Enforces: AC-2 (Account Management), AC-6 (Least Privilege)
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

# -- AC-2/AC-6: Access Group (auditor, read-only) -----------------------------

resource "ibm_iam_access_group" "auditors" {
  name        = "${var.name_prefix}-auditors"
  description = "Warlock-managed auditor access group with viewer permissions"
  tags        = local.common_tags
}

# -- AC-6: Viewer Policy for Auditors -----------------------------------------

resource "ibm_iam_access_group_policy" "viewer" {
  access_group_id = ibm_iam_access_group.auditors.id
  roles           = ["Viewer"]

  resources {
    resource_group_id = var.resource_group_id
  }
}

# -- AC-2: Account Settings (MFA, restrict service ID creation) ---------------

resource "ibm_iam_account_settings" "strict" {
  mfa                             = "LEVEL3"
  restrict_create_service_id      = "RESTRICTED"
  restrict_create_platform_apikey = "RESTRICTED"
  session_expiration_in_seconds   = "3600"
  session_invalidation_in_seconds = "900"
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/ibm-iam"
  resource_id    = ibm_iam_access_group.auditors.id
  control_ids    = ["AC-2", "AC-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    mfa_level                  = "LEVEL3"
    restrict_service_id        = "RESTRICTED"
    session_expiration_seconds = "3600"
  }
}
