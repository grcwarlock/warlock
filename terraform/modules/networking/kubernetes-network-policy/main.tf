###############################################################################
# Kubernetes Network Policy Module
# Enforces: SC-7 (Boundary Protection)
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

# -- SC-7: Default deny all ingress ------------------------------------------

resource "kubernetes_network_policy" "default_deny" {
  metadata {
    name      = "${var.name_prefix}-default-deny-ingress"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {}

    policy_types = ["Ingress"]
  }
}

# -- SC-7: Allow from same namespace -----------------------------------------

resource "kubernetes_network_policy" "allow_same_namespace" {
  metadata {
    name      = "${var.name_prefix}-allow-same-namespace"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {}

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = var.namespace
          }
        }
      }
    }

    policy_types = ["Ingress"]
  }
}

# -- SC-7: Allow from specific namespaces on specific ports ------------------

resource "kubernetes_network_policy" "allow_specific" {
  count = length(var.allowed_namespaces) > 0 ? 1 : 0

  metadata {
    name      = "${var.name_prefix}-allow-specific"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    pod_selector {}

    dynamic "ingress" {
      for_each = [1]
      content {
        dynamic "from" {
          for_each = var.allowed_namespaces
          content {
            namespace_selector {
              match_labels = {
                "kubernetes.io/metadata.name" = from.value
              }
            }
          }
        }

        dynamic "ports" {
          for_each = var.allowed_ports
          content {
            port     = ports.value
            protocol = "TCP"
          }
        }
      }
    }

    policy_types = ["Ingress"]
  }
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/kubernetes-network-policy"
  resource_id    = kubernetes_network_policy.default_deny.id
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    namespace            = var.namespace
    allowed_namespaces   = join(",", var.allowed_namespaces)
    allowed_ports        = join(",", [for p in var.allowed_ports : tostring(p)])
    default_deny_enabled = "true"
  }
}
