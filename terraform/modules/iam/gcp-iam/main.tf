###############################################################################
# GCP IAM Hardening
# Enforces: AC-2 (Account Management), AC-6 (Least Privilege), IA-2 (Identification)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

locals {
  common_labels = merge(var.labels, { managed_by = "warlock" })
}

# -- AC-6: Custom auditor role with minimal read permissions ------------------

resource "google_project_iam_custom_role" "auditor" {
  project     = var.project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_auditor"
  title       = "${var.name_prefix} Auditor"
  description = "Minimal read-only auditor role for compliance review (AC-6)"

  permissions = [
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "logging.logEntries.list",
    "logging.logs.list",
    "logging.sinks.list",
    "monitoring.metricDescriptors.list",
    "monitoring.timeSeries.list",
    "compute.instances.list",
    "compute.networks.list",
    "compute.firewalls.list",
    "storage.buckets.list",
    "iam.serviceAccounts.list",
    "iam.roles.list",
  ]
}

# -- AC-2: Bind auditor role to specified members -----------------------------

resource "google_project_iam_member" "auditor_binding" {
  for_each = toset(var.auditor_members)

  project = var.project_id
  role    = google_project_iam_custom_role.auditor.id
  member  = each.value
}

# -- AC-6: Organization policy — domain restricted sharing (optional) ---------

resource "google_project_organization_policy" "domain_restricted_sharing" {
  count = var.enable_domain_restriction ? 1 : 0

  project    = var.project_id
  constraint = "iam.allowedPolicyMemberDomains"

  list_policy {
    allow {
      values = var.allowed_domains
    }
  }

  lifecycle {
    precondition {
      condition     = length(var.allowed_domains) > 0
      error_message = "allowed_domains must not be empty when enable_domain_restriction is true."
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/gcp-iam"
  resource_id    = google_project_iam_custom_role.auditor.id
  control_ids    = ["AC-2", "AC-6", "IA-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    auditor_role_id      = google_project_iam_custom_role.auditor.role_id
    auditor_member_count = tostring(length(var.auditor_members))
    domain_restriction   = tostring(var.enable_domain_restriction)
  }
}
