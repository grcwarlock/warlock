###############################################################################
# Kubernetes RBAC Module
# Enforces: AC-2 (Account Management), AC-6 (Least Privilege)
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
}

# -- AC-6: Auditor ClusterRole (read-only on core resources) -----------------

resource "kubernetes_cluster_role" "auditor" {
  metadata {
    name   = "${var.name_prefix}-auditor"
    labels = local.common_labels
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "services", "configmaps", "namespaces", "nodes", "persistentvolumeclaims", "serviceaccounts"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies", "ingresses"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["rbac.authorization.k8s.io"]
    resources  = ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["policy"]
    resources  = ["podsecuritypolicies", "poddisruptionbudgets"]
    verbs      = ["get", "list", "watch"]
  }
}

# -- AC-2: ClusterRoleBinding ------------------------------------------------

resource "kubernetes_cluster_role_binding" "auditor" {
  metadata {
    name   = "${var.name_prefix}-auditor-binding"
    labels = local.common_labels
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.auditor.metadata[0].name
  }

  dynamic "subject" {
    for_each = var.subjects
    content {
      kind      = subject.value.kind
      name      = subject.value.name
      namespace = lookup(subject.value, "namespace", null)
      api_group = subject.value.kind == "ServiceAccount" ? "" : "rbac.authorization.k8s.io"
    }
  }
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "iam/kubernetes-rbac"
  resource_id    = kubernetes_cluster_role.auditor.id
  control_ids    = ["AC-2", "AC-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    role_name     = kubernetes_cluster_role.auditor.metadata[0].name
    binding_name  = kubernetes_cluster_role_binding.auditor.metadata[0].name
    subject_count = tostring(length(var.subjects))
  }
}
