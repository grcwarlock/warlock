###############################################################################
# Kubernetes Secure Deployment Module
# Enforces: SC-7 (Boundary Protection), CM-6 (Configuration Management)
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
    "app.kubernetes.io/name"       = var.name_prefix
  })
}

# -- CM-6: Hardened Deployment -----------------------------------------------

resource "kubernetes_deployment" "main" {
  metadata {
    name      = "${var.name_prefix}-deployment"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = {
        "app.kubernetes.io/name" = var.name_prefix
      }
    }

    template {
      metadata {
        labels = local.common_labels
      }

      spec {
        automount_service_account_token = false

        security_context {
          run_as_non_root = true
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name  = var.name_prefix
          image = var.image

          port {
            container_port = var.container_port
            protocol       = "TCP"
          }

          resources {
            limits = {
              cpu    = var.cpu_limit
              memory = var.memory_limit
            }
            requests = {
              cpu    = var.cpu_limit
              memory = var.memory_limit
            }
          }

          security_context {
            run_as_non_root            = true
            read_only_root_filesystem  = true
            allow_privilege_escalation = false
            privileged                 = false
            capabilities {
              drop = ["ALL"]
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = var.container_port
            }
            initial_delay_seconds = 15
            period_seconds        = 20
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = var.container_port
            }
            initial_delay_seconds = 5
            period_seconds        = 10
          }
        }
      }
    }
  }
}

# -- SC-7: ClusterIP Service ------------------------------------------------

resource "kubernetes_service" "main" {
  metadata {
    name      = "${var.name_prefix}-service"
    namespace = var.namespace
    labels    = local.common_labels
  }

  spec {
    selector = {
      "app.kubernetes.io/name" = var.name_prefix
    }

    port {
      port        = var.container_port
      target_port = var.container_port
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/kubernetes-deployment"
  resource_id    = kubernetes_deployment.main.id
  control_ids    = ["SC-7", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    namespace             = var.namespace
    image                 = var.image
    replicas              = tostring(var.replicas)
    run_as_non_root       = "true"
    read_only_root_fs     = "true"
    drop_all_capabilities = "true"
  }
}
