###############################################################################
# DigitalOcean App Platform — Warlock Deployment
# Enforces: SC-7 (Boundary Protection), SC-28 (Encryption at Rest)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.34" }
  }
}

# -- SC-7/SC-28: App Platform with service, worker, database ------------------

resource "digitalocean_app" "warlock" {
  spec {
    name   = "${var.name_prefix}-warlock"
    region = var.region

    # Warlock API service
    service {
      name               = "warlock-api"
      instance_count     = var.instance_count
      instance_size_slug = var.instance_size

      image {
        registry_type = "DOCKER_HUB"
        registry      = var.container_image
        repository    = var.container_image
        tag           = "latest"
      }

      http_port = 8000

      health_check {
        http_path = "/health"
      }
    }

    # Warlock background worker
    worker {
      name               = "warlock-worker"
      instance_count     = 1
      instance_size_slug = var.instance_size

      image {
        registry_type = "DOCKER_HUB"
        registry      = var.container_image
        repository    = var.container_image
        tag           = "latest"
      }
    }

    # Managed PostgreSQL database component
    database {
      name         = "warlock-db"
      engine       = "PG"
      version      = "15"
      production   = var.instance_count > 1
      cluster_name = "${var.name_prefix}-db"
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "deploy/digitalocean-app"
  resource_id    = digitalocean_app.warlock.id
  control_ids    = ["SC-7", "SC-28"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    region         = var.region
    instance_count = tostring(var.instance_count)
    instance_size  = var.instance_size
    database       = "pg-15"
  }
}
