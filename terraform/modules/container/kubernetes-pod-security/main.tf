###############################################################################
# Kubernetes Pod Security Standards Module
# Enforces: AC-3 (Access Enforcement), CM-6 (Configuration Management)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.25" }
  }
}

locals {
  common_labels = merge(var.labels, {
    "app.kubernetes.io/managed-by" = "warlock"
    "warlock.dev/framework"        = "NIST-800-53"
  })

  pss_labels = {
    "pod-security.kubernetes.io/enforce"         = var.enforcement_level
    "pod-security.kubernetes.io/enforce-version" = "latest"
    "pod-security.kubernetes.io/audit"           = var.enforcement_level
    "pod-security.kubernetes.io/audit-version"   = "latest"
    "pod-security.kubernetes.io/warn"            = var.enforcement_level
    "pod-security.kubernetes.io/warn-version"    = "latest"
  }
}

# -- AC-3 / CM-6: Namespaces with Pod Security Standards --------------------

resource "kubernetes_namespace" "pss" {
  for_each = toset(var.namespaces)

  metadata {
    name   = each.value
    labels = merge(local.common_labels, local.pss_labels)
  }
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "container/kubernetes-pod-security"
  resource_id    = "${var.name_prefix}-pod-security-standards"
  control_ids    = ["AC-3", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    enforcement_level = var.enforcement_level
    namespace_count   = tostring(length(var.namespaces))
    namespaces        = join(",", var.namespaces)
  }
}
