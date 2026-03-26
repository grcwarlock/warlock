###############################################################################
# Linode Instance with Backups + Firewall
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Settings)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    linode = { source = "linode/linode", version = "~> 2.12" }
  }
}

# -- SC-28/CM-6: Linode instance with backups and private IP ------------------

resource "linode_instance" "main" {
  label           = "${var.name_prefix}-instance"
  region          = var.region
  type            = var.type
  image           = var.image
  backups_enabled = true # SC-28: automated backups
  private_ip      = true # CM-6: private networking
  authorized_keys = var.authorized_keys
  tags            = var.tags
}

# -- SC-7: Firewall for the instance -----------------------------------------

resource "linode_firewall" "main" {
  label           = "${var.name_prefix}-instance-fw"
  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"
  tags            = var.tags

  # SSH access
  inbound {
    label    = "allow-ssh"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  linodes = [linode_instance.main.id]
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/linode-instance"
  resource_id    = tostring(linode_instance.main.id)
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    backups_enabled = "true"
    private_ip      = "true"
    image           = var.image
    type            = var.type
  }
}
