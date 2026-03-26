###############################################################################
# DigitalOcean Managed Database Cluster
# Enforces: SC-28 (Encryption at Rest), SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.34" }
  }
}

# -- SC-28: Managed database with encryption at rest (provider-managed) -------

resource "digitalocean_database_cluster" "main" {
  name                 = "${var.name_prefix}-db"
  engine               = var.engine
  version              = var.engine_version
  size                 = var.size
  region               = var.region
  node_count           = var.node_count
  private_network_uuid = var.vpc_uuid
  tags                 = var.tags
}

# -- SC-7: Database firewall — trusted sources only ---------------------------

resource "digitalocean_database_firewall" "main" {
  cluster_id = digitalocean_database_cluster.main.id

  dynamic "rule" {
    for_each = var.trusted_source_ids
    content {
      type  = "droplet"
      value = rule.value
    }
  }
}

# -- Application database -----------------------------------------------------

resource "digitalocean_database_db" "warlock" {
  cluster_id = digitalocean_database_cluster.main.id
  name       = "${var.name_prefix}_app"
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "database/digitalocean-db"
  resource_id    = digitalocean_database_cluster.main.urn
  control_ids    = ["SC-28", "SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    engine               = var.engine
    engine_version       = var.engine_version
    node_count           = tostring(var.node_count)
    private_network      = tostring(var.vpc_uuid != null)
    firewall_rules_count = tostring(length(var.trusted_source_ids))
  }
}
