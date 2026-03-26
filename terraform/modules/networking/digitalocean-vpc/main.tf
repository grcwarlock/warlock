###############################################################################
# DigitalOcean VPC + Firewall
# Enforces: SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.34" }
  }
}

# -- SC-7: VPC with private IP range ------------------------------------------

resource "digitalocean_vpc" "main" {
  name     = "${var.name_prefix}-vpc"
  region   = var.region
  ip_range = var.ip_range
}

# -- SC-7: Firewall — deny all inbound by default, allow specific ports -------

resource "digitalocean_firewall" "main" {
  name        = "${var.name_prefix}-firewall"
  droplet_ids = var.droplet_ids
  tags        = var.tags

  # Deny all inbound by default; only allow specified ports
  dynamic "inbound_rule" {
    for_each = var.allowed_inbound_ports
    content {
      protocol         = inbound_rule.value.protocol
      port_range       = inbound_rule.value.port_range
      source_addresses = inbound_rule.value.source_addresses
    }
  }

  # Allow all outbound by default (required for package updates, DNS, etc.)
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/digitalocean-vpc"
  resource_id    = digitalocean_vpc.main.id
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    vpc_region             = var.region
    ip_range               = var.ip_range
    inbound_rules_count    = tostring(length(var.allowed_inbound_ports))
    default_inbound_policy = "deny"
  }
}
