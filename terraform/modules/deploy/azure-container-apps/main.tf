###############################################################################
# Warlock Deployment — Azure Container Apps
# Deploys: FastAPI API + Pipeline Worker + PostgreSQL Flexible Server +
#          Redis Cache + Key Vault + Log Analytics
# Enforces: SC-7 (Network Segmentation), SC-28 (Encryption at Rest), AU-2 (Logging)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
    random  = { source = "hashicorp/random", version = "~> 3.0" }
  }
}

data "azurerm_client_config" "current" {}

locals {
  common_tags = merge(var.tags, {
    ManagedBy   = "warlock"
    Environment = var.environment
    Team        = var.team
    Framework   = "NIST-800-53"
  })
}

# -----------------------------------------------------------------------------
# Resource Group
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "warlock" {
  name     = "${var.name_prefix}-warlock-rg"
  location = var.location

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# AU-2: Log Analytics Workspace
# -----------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "warlock" {
  name                = "${var.name_prefix}-warlock-logs"
  location            = azurerm_resource_group.warlock.location
  resource_group_name = azurerm_resource_group.warlock.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# SC-28: Key Vault — store WLK_JWT_SECRET
# -----------------------------------------------------------------------------

resource "azurerm_key_vault" "warlock" {
  name                       = "${var.name_prefix}-wlk-kv"
  location                   = azurerm_resource_group.warlock.location
  resource_group_name        = azurerm_resource_group.warlock.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Purge",
    ]
  }

  tags = local.common_tags
}

resource "azurerm_key_vault_secret" "jwt_secret" {
  name         = "wlk-jwt-secret"
  value        = var.wlk_jwt_secret
  key_vault_id = azurerm_key_vault.warlock.id
}

# -----------------------------------------------------------------------------
# SC-28: PostgreSQL Flexible Server — encrypted storage
# -----------------------------------------------------------------------------

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "azurerm_postgresql_flexible_server" "warlock" {
  name                = "${var.name_prefix}-warlock-pg"
  location            = azurerm_resource_group.warlock.location
  resource_group_name = azurerm_resource_group.warlock.name

  version  = "15"
  sku_name = var.db_sku_name

  administrator_login    = "warlock"
  administrator_password = random_password.db_password.result

  storage_mb                   = 32768
  backup_retention_days        = 7
  geo_redundant_backup_enabled = false

  zone = "1"

  tags = local.common_tags
}

resource "azurerm_postgresql_flexible_server_database" "warlock" {
  name      = "warlock"
  server_id = azurerm_postgresql_flexible_server.warlock.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure" {
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.warlock.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# -----------------------------------------------------------------------------
# SC-28: Redis Cache — TLS 1.2 minimum
# -----------------------------------------------------------------------------

resource "azurerm_redis_cache" "warlock" {
  name                = "${var.name_prefix}-warlock-redis"
  location            = azurerm_resource_group.warlock.location
  resource_group_name = azurerm_resource_group.warlock.name
  capacity            = 0
  family              = "C"
  sku_name            = var.redis_sku
  minimum_tls_version = "1.2"

  redis_configuration {
  }

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Container App Environment
# -----------------------------------------------------------------------------

resource "azurerm_container_app_environment" "warlock" {
  name                       = "${var.name_prefix}-warlock-env"
  location                   = azurerm_resource_group.warlock.location
  resource_group_name        = azurerm_resource_group.warlock.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.warlock.id

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Container App: warlock-api (port 8000, with ingress)
# -----------------------------------------------------------------------------

locals {
  db_url = format(
    "postgresql://%s:%s@%s:5432/%s",
    "warlock",
    random_password.db_password.result,
    azurerm_postgresql_flexible_server.warlock.fqdn,
    "warlock"
  )

  redis_url = format(
    "rediss://:%s@%s:%d/0",
    azurerm_redis_cache.warlock.primary_access_key,
    azurerm_redis_cache.warlock.hostname,
    azurerm_redis_cache.warlock.ssl_port
  )

  shared_env = [
    { name = "WLK_DATABASE_URL", value = local.db_url },
    { name = "WLK_REDIS_URL", value = local.redis_url },
    { name = "WLK_AI_ENABLED", value = var.wlk_ai_enabled },
    { name = "WLK_OPA_URL", value = var.wlk_opa_url },
  ]

  secret_env = [
    { name = "wlk-jwt-secret", value = var.wlk_jwt_secret },
  ]
}

resource "azurerm_container_app" "api" {
  name                         = "${var.name_prefix}-warlock-api"
  container_app_environment_id = azurerm_container_app_environment.warlock.id
  resource_group_name          = azurerm_resource_group.warlock.name
  revision_mode                = "Single"

  secret {
    name  = "wlk-jwt-secret"
    value = var.wlk_jwt_secret
  }

  secret {
    name  = "wlk-database-url"
    value = local.db_url
  }

  secret {
    name  = "wlk-redis-url"
    value = local.redis_url
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = "warlock-api"
      image  = var.container_image
      cpu    = var.api_cpu
      memory = var.api_memory

      env {
        name        = "WLK_JWT_SECRET"
        secret_name = "wlk-jwt-secret"
      }

      env {
        name        = "WLK_DATABASE_URL"
        secret_name = "wlk-database-url"
      }

      env {
        name        = "WLK_REDIS_URL"
        secret_name = "wlk-redis-url"
      }

      env {
        name  = "WLK_AI_ENABLED"
        value = var.wlk_ai_enabled
      }

      env {
        name  = "WLK_OPA_URL"
        value = var.wlk_opa_url
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = 8000
      }

      readiness_probe {
        transport = "HTTP"
        path      = "/readyz"
        port      = 8000
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Container App: warlock-worker (no ingress)
# -----------------------------------------------------------------------------

resource "azurerm_container_app" "worker" {
  name                         = "${var.name_prefix}-warlock-worker"
  container_app_environment_id = azurerm_container_app_environment.warlock.id
  resource_group_name          = azurerm_resource_group.warlock.name
  revision_mode                = "Single"

  secret {
    name  = "wlk-jwt-secret"
    value = var.wlk_jwt_secret
  }

  secret {
    name  = "wlk-database-url"
    value = local.db_url
  }

  secret {
    name  = "wlk-redis-url"
    value = local.redis_url
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "warlock-worker"
      image  = var.container_image
      cpu    = var.api_cpu
      memory = var.api_memory

      command = ["python", "-m", "warlock.pipeline.scheduler"]

      env {
        name        = "WLK_JWT_SECRET"
        secret_name = "wlk-jwt-secret"
      }

      env {
        name        = "WLK_DATABASE_URL"
        secret_name = "wlk-database-url"
      }

      env {
        name        = "WLK_REDIS_URL"
        secret_name = "wlk-redis-url"
      }

      env {
        name  = "WLK_AI_ENABLED"
        value = var.wlk_ai_enabled
      }

      env {
        name  = "WLK_OPA_URL"
        value = var.wlk_opa_url
      }
    }
  }

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# Warlock closed-loop registration
# -----------------------------------------------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "deploy/azure-container-apps"
  resource_id    = azurerm_container_app.api.id
  control_ids    = ["SC-7", "SC-28", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    min_replicas  = tostring(var.min_replicas)
    max_replicas  = tostring(var.max_replicas)
    db_sku        = var.db_sku_name
    redis_tls     = "1.2"
    log_analytics = "true"
  }
}
