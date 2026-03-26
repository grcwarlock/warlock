###############################################################################
# DigitalOcean Droplet with SSH Key + Firewall
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Settings)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.34" }
  }
}

# -- CM-6: SSH Key for secure access ------------------------------------------

resource "digitalocean_ssh_key" "main" {
  name       = "${var.name_prefix}-ssh-key"
  public_key = var.ssh_public_key
}

# -- SC-28/CM-6: Droplet with monitoring, IPv6, backups -----------------------

resource "digitalocean_droplet" "main" {
  name       = "${var.name_prefix}-droplet"
  region     = var.region
  size       = var.size
  image      = var.image
  monitoring = true # CM-6: enable built-in monitoring agent
  ipv6       = true # CM-6: dual-stack networking
  backups    = true # SC-28: automated backup snapshots
  vpc_uuid   = var.vpc_uuid
  ssh_keys   = [digitalocean_ssh_key.main.fingerprint]
  tags       = var.tags
}

# -- SC-7: Firewall for the droplet ------------------------------------------

resource "digitalocean_firewall" "main" {
  name        = "${var.name_prefix}-droplet-fw"
  droplet_ids = [digitalocean_droplet.main.id]

  # SSH access only
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Allow all outbound
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
  module_name    = "compute/digitalocean-droplet"
  resource_id    = digitalocean_droplet.main.urn
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    monitoring_enabled = "true"
    ipv6_enabled       = "true"
    backups_enabled    = "true"
    image              = var.image
    size               = var.size
  }
}
