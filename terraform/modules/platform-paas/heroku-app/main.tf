###############################################################################
# Heroku App Deployment
# Enforces: SC-7 (Boundary Protection), CM-6 (Configuration Settings)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    heroku = { source = "heroku/heroku", version = "~> 5.2" }
  }
}

locals {
  common_tags = {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  }
}

# -- Heroku Application -------------------------------------------------------

resource "heroku_app" "main" {
  name   = var.app_name
  region = var.region
  stack  = "heroku-22"

  organization {
    name = var.name_prefix
  }

  sensitive_config_vars = var.env_vars
}

# -- CM-6: Heroku Addon — PostgreSQL -------------------------------------------

resource "heroku_addon" "postgresql" {
  app_id = heroku_app.main.id
  plan   = "heroku-postgresql:mini"
}

# -- CM-6: App Config Association — WLK_* environment variables ----------------

resource "heroku_app_config_association" "warlock" {
  app_id = heroku_app.main.id

  vars = {
    WLK_OPA_FAIL_MODE = "closed"
    WLK_LOG_LEVEL     = "INFO"
    WLK_AI_ENABLED    = "false"
  }

  sensitive_vars = var.env_vars
}

# -- SC-7: Formation (dyno scaling) -------------------------------------------

resource "heroku_formation" "web" {
  app_id   = heroku_app.main.id
  type     = "web"
  quantity = var.formation_quantity
  size     = var.formation_size

  depends_on = [heroku_addon.postgresql]
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "platform-paas/heroku-app"
  resource_id    = heroku_app.main.id
  control_ids    = ["SC-7", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    app_name = var.app_name
    region   = var.region
    stack    = "heroku-22"
  }
}
