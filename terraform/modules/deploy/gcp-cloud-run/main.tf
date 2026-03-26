###############################################################################
# Warlock Deployment — GCP Cloud Run
# Deploys: FastAPI API + Pipeline Worker + Cloud SQL PostgreSQL +
#          Memorystore Redis + Secret Manager
# Enforces: SC-7 (Network Segmentation), SC-28 (Encryption at Rest), AU-2 (Logging)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

locals {
  common_labels = merge(var.labels, {
    managed-by  = "warlock"
    environment = var.environment
    team        = var.team
    framework   = "nist-800-53"
  })

  required_apis = [
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "secretmanager.googleapis.com",
    "servicenetworking.googleapis.com",
    "vpcaccess.googleapis.com",
  ]
}

# -----------------------------------------------------------------------------
# Enable required GCP APIs
# -----------------------------------------------------------------------------

resource "google_project_service" "apis" {
  for_each = toset(local.required_apis)

  project = var.project_id
  service = each.value

  disable_on_destroy = false
}

# -----------------------------------------------------------------------------
# SC-7: VPC Network + Private Services Access
# -----------------------------------------------------------------------------

resource "google_compute_network" "warlock" {
  name                    = "${var.name_prefix}-warlock-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "warlock" {
  name          = "${var.name_prefix}-warlock-subnet"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.warlock.id
  ip_cidr_range = "10.0.0.0/24"

  private_ip_google_access = true
}

resource "google_compute_global_address" "private_services" {
  name          = "${var.name_prefix}-warlock-private-ip"
  project       = var.project_id
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.warlock.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.warlock.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]

  depends_on = [google_project_service.apis]
}

# -- VPC Access Connector for Cloud Run --------------------------------------

resource "google_vpc_access_connector" "warlock" {
  name          = "${var.name_prefix}-wlk-conn"
  project       = var.project_id
  region        = var.region
  network       = google_compute_network.warlock.name
  ip_cidr_range = "10.8.0.0/28"

  depends_on = [google_project_service.apis]
}

# -----------------------------------------------------------------------------
# SC-28: Secret Manager — WLK_JWT_SECRET
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "${var.name_prefix}-wlk-jwt-secret"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = local.common_labels

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "jwt_secret" {
  secret      = google_secret_manager_secret.jwt_secret.id
  secret_data = var.wlk_jwt_secret
}

# -----------------------------------------------------------------------------
# SC-28: Cloud SQL PostgreSQL — private network, encrypted
# -----------------------------------------------------------------------------

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "warlock" {
  name             = "${var.name_prefix}-warlock-pg"
  project          = var.project_id
  region           = var.region
  database_version = "POSTGRES_15"

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"
    disk_autoresize   = true
    disk_size         = 20
    disk_type         = "PD_SSD"

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = google_compute_network.warlock.id
      enable_private_path_for_google_cloud_services = true
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    user_labels = local.common_labels
  }

  deletion_protection = var.deletion_protection

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "warlock" {
  name     = "warlock"
  project  = var.project_id
  instance = google_sql_database_instance.warlock.name
}

resource "google_sql_user" "warlock" {
  name     = "warlock"
  project  = var.project_id
  instance = google_sql_database_instance.warlock.name
  password = random_password.db_password.result
}

# -----------------------------------------------------------------------------
# SC-28: Memorystore Redis — auth enabled, private network
# -----------------------------------------------------------------------------

resource "random_password" "redis_auth" {
  length  = 32
  special = false
}

resource "google_redis_instance" "warlock" {
  name           = "${var.name_prefix}-warlock-redis"
  project        = var.project_id
  region         = var.region
  tier           = "BASIC"
  memory_size_gb = var.redis_memory_size_gb
  redis_version  = "REDIS_7_0"

  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  authorized_network = google_compute_network.warlock.id

  labels = local.common_labels

  depends_on = [google_project_service.apis]
}

# -----------------------------------------------------------------------------
# Cloud Run: warlock-api (port 8000, public ingress)
# -----------------------------------------------------------------------------

locals {
  db_url = format(
    "postgresql://warlock:%s@%s:5432/warlock",
    random_password.db_password.result,
    google_sql_database_instance.warlock.private_ip_address
  )

  redis_url = format(
    "redis://:%s@%s:%d/0",
    google_redis_instance.warlock.auth_string,
    google_redis_instance.warlock.host,
    google_redis_instance.warlock.port
  )
}

resource "google_cloud_run_v2_service" "api" {
  name     = "${var.name_prefix}-warlock-api"
  project  = var.project_id
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    vpc_access {
      connector = google_vpc_access_connector.warlock.id
      egress    = "ALL_TRAFFIC"
    }

    containers {
      image = var.container_image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }

      env {
        name  = "WLK_DATABASE_URL"
        value = local.db_url
      }

      env {
        name  = "WLK_REDIS_URL"
        value = local.redis_url
      }

      env {
        name  = "WLK_AI_ENABLED"
        value = var.wlk_ai_enabled
      }

      env {
        name  = "WLK_OPA_URL"
        value = var.wlk_opa_url
      }

      env {
        name = "WLK_JWT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_secret.secret_id
            version = "latest"
          }
        }
      }

      startup_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        initial_delay_seconds = 10
        period_seconds        = 5
        failure_threshold     = 5
      }

      liveness_probe {
        http_get {
          path = "/health"
          port = 8000
        }
        period_seconds = 15
      }
    }
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.apis,
    google_sql_database.warlock,
    google_sql_user.warlock,
  ]
}

# -- Allow unauthenticated access to the API ---------------------------------

resource "google_cloud_run_v2_service_iam_member" "api_public" {
  project  = google_cloud_run_v2_service.api.project
  location = google_cloud_run_v2_service.api.location
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# -----------------------------------------------------------------------------
# Cloud Run: warlock-worker (no port, pipeline scheduler)
# -----------------------------------------------------------------------------

resource "google_cloud_run_v2_service" "worker" {
  name     = "${var.name_prefix}-warlock-worker"
  project  = var.project_id
  location = var.region
  ingress  = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    scaling {
      min_instance_count = 1
      max_instance_count = 1
    }

    vpc_access {
      connector = google_vpc_access_connector.warlock.id
      egress    = "ALL_TRAFFIC"
    }

    containers {
      image   = var.container_image
      command = ["python", "-m", "warlock.pipeline.scheduler"]

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }

      env {
        name  = "WLK_DATABASE_URL"
        value = local.db_url
      }

      env {
        name  = "WLK_REDIS_URL"
        value = local.redis_url
      }

      env {
        name  = "WLK_AI_ENABLED"
        value = var.wlk_ai_enabled
      }

      env {
        name  = "WLK_OPA_URL"
        value = var.wlk_opa_url
      }

      env {
        name = "WLK_JWT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_secret.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  labels = local.common_labels

  depends_on = [
    google_project_service.apis,
    google_sql_database.warlock,
    google_sql_user.warlock,
  ]
}

# -----------------------------------------------------------------------------
# Warlock closed-loop registration
# -----------------------------------------------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "deploy/gcp-cloud-run"
  resource_id    = google_cloud_run_v2_service.api.id
  control_ids    = ["SC-7", "SC-28", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    min_instances        = tostring(var.min_instances)
    max_instances        = tostring(var.max_instances)
    db_tier              = var.db_tier
    redis_auth           = "true"
    private_services_vpc = "true"
  }
}
