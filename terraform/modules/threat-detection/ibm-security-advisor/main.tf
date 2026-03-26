###############################################################################
# IBM Cloud Security & Compliance Center Baseline
# Enforces: SI-4 (System Monitoring), AU-6 (Audit Review / Analysis)
#
# Note: IBM SCC Terraform resources are limited. This module provisions
# the SCC instance and attaches a profile for continuous compliance
# monitoring. Some SCC features require console configuration.
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

# -- SI-4: Security & Compliance Center Instance -------------------------------

resource "ibm_resource_instance" "scc" {
  name              = "${var.name_prefix}-scc"
  service           = "compliance"
  plan              = "security-compliance-center-standard-plan"
  location          = var.region
  resource_group_id = var.resource_group_id
  tags              = local.common_tags
}

# -- SI-4/AU-6: SCC Profile Attachment ----------------------------------------
# Attaches a predefined compliance profile (e.g. IBM Cloud Best Practices)
# to continuously monitor the account.

resource "ibm_scc_profile_attachment" "main" {
  instance_id = ibm_resource_instance.scc.guid
  profile_id  = var.profile_id
  name        = "${var.name_prefix}-attachment"
  description = "Warlock-managed SCC profile attachment for continuous compliance"

  scope {
    environment = "ibm-cloud"

    properties {
      name  = "scope_id"
      value = var.resource_group_id
    }
    properties {
      name  = "scope_type"
      value = "account.resource_group"
    }
  }

  schedule = "daily"
  status   = "enabled"
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "threat-detection/ibm-security-advisor"
  resource_id    = ibm_resource_instance.scc.id
  control_ids    = ["SI-4", "AU-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    schedule = "daily"
    region   = var.region
  }
}
