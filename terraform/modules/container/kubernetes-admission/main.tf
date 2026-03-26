###############################################################################
# Kubernetes Admission Control Module
# Enforces: CM-6 (Configuration Management), SI-3 (Malicious Code Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.25" }
    helm       = { source = "hashicorp/helm", version = "~> 2.12" }
  }
}

locals {
  common_labels = merge(var.labels, {
    "app.kubernetes.io/managed-by" = "warlock"
    "warlock.dev/framework"        = "NIST-800-53"
  })

  # Chart configuration per policy engine
  engine_config = {
    gatekeeper = {
      repository = "https://open-policy-agent.github.io/gatekeeper/charts"
      chart      = "gatekeeper"
      version    = var.chart_version != null ? var.chart_version : "3.14.0"
    }
    kyverno = {
      repository = "https://kyverno.github.io/kyverno"
      chart      = "kyverno"
      version    = var.chart_version != null ? var.chart_version : "3.1.0"
    }
  }

  selected_engine = local.engine_config[var.policy_engine]
}

# -- Namespace for policy system ---------------------------------------------

resource "kubernetes_namespace" "policy_system" {
  metadata {
    name   = "${var.name_prefix}-policy-system"
    labels = local.common_labels
  }
}

# -- CM-6 / SI-3: Admission controller via Helm -----------------------------

resource "helm_release" "admission_controller" {
  name       = "${var.name_prefix}-${var.policy_engine}"
  namespace  = kubernetes_namespace.policy_system.metadata[0].name
  repository = local.selected_engine.repository
  chart      = local.selected_engine.chart
  version    = local.selected_engine.version

  create_namespace = false
  wait             = true
  timeout          = 600

  set {
    name  = "replicas"
    value = "2"
  }

  set {
    name  = "auditInterval"
    value = "60"
  }
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "container/kubernetes-admission"
  resource_id    = kubernetes_namespace.policy_system.id
  control_ids    = ["CM-6", "SI-3"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    policy_engine = var.policy_engine
    chart_version = local.selected_engine.version
    namespace     = kubernetes_namespace.policy_system.metadata[0].name
  }
}
