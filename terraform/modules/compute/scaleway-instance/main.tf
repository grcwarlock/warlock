###############################################################################
# Scaleway Instance Server
# Enforces: SC-28 (Encryption at Rest), CM-6 (Secure Configuration)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    scaleway = { source = "scaleway/scaleway", version = "~> 2.30" }
  }
}

# -- CM-6, SC-28: Hardened instance -------------------------------------------

resource "scaleway_instance_server" "main" {
  name  = "${var.name_prefix}-server"
  zone  = var.zone
  type  = var.type
  image = var.image

  # CM-6: Disable dynamic IP — use explicit IP assignment only
  enable_dynamic_ip = false

  # SC-28: Root volume is encrypted by default on Scaleway
  tags = concat(var.tags, ["managed-by:warlock", "framework:nist-800-53"])

  # CM-6: Attach to security group if provided
  security_group_id = var.security_group_id

  ip_id = var.enable_public_ip ? scaleway_instance_ip.public[0].id : null
}

# -- Optional public IP (disabled by default for private-only) ----------------

resource "scaleway_instance_ip" "public" {
  count = var.enable_public_ip ? 1 : 0

  zone = var.zone
  tags = concat(var.tags, ["managed-by:warlock"])
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/scaleway-instance"
  resource_id    = scaleway_instance_server.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    type              = var.type
    image             = var.image
    ipv6_enabled      = "true"
    dynamic_ip        = "false"
    public_ip_enabled = tostring(var.enable_public_ip)
  }
}
