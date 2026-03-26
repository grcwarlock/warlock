###############################################################################
# Hetzner Cloud Server
# Enforces: SC-28 (Encryption at Rest), CM-6 (Secure Configuration)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    hcloud = { source = "hetznercloud/hcloud", version = "~> 1.45" }
  }
}

# -- CM-6: SSH key for secure access ------------------------------------------

resource "hcloud_ssh_key" "main" {
  name       = "${var.name_prefix}-ssh-key"
  public_key = var.ssh_public_key
  labels     = merge(var.labels, { managed-by = "warlock", framework = "nist-800-53" })
}

# -- SC-28, CM-6: Hardened server with backups --------------------------------

resource "hcloud_server" "main" {
  name        = "${var.name_prefix}-server"
  server_type = var.server_type
  location    = var.location
  image       = var.image

  # CM-6: Backups enabled for disaster recovery
  backups = true

  # CM-6: SSH key authentication (no password)
  ssh_keys = [hcloud_ssh_key.main.id]

  # SC-7: Attach firewall if provided
  firewall_ids = var.firewall_ids

  labels = merge(var.labels, { managed-by = "warlock", framework = "nist-800-53" })
}

# -- SC-28: Optional encrypted volume ----------------------------------------

resource "hcloud_volume" "data" {
  count = var.enable_data_volume ? 1 : 0

  name      = "${var.name_prefix}-data-volume"
  size      = var.data_volume_size_gb
  server_id = hcloud_server.main.id
  location  = var.location

  # SC-28: Hetzner volumes are encrypted at rest by default
  labels = merge(var.labels, { managed-by = "warlock", framework = "nist-800-53" })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/hetzner-server"
  resource_id    = hcloud_server.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    server_type     = var.server_type
    location        = var.location
    backups_enabled = "true"
    ssh_key_auth    = "true"
    data_volume     = tostring(var.enable_data_volume)
  }
}
