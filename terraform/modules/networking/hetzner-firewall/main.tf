###############################################################################
# Hetzner Cloud Firewall
# Enforces: SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    hcloud = { source = "hetznercloud/hcloud", version = "~> 1.45" }
  }
}

# -- SC-7: Firewall with deny-all default, explicit allow rules ---------------

resource "hcloud_firewall" "main" {
  name   = "${var.name_prefix}-firewall"
  labels = merge(var.labels, { managed-by = "warlock", framework = "nist-800-53" })

  # SC-7: Allow only explicitly specified inbound ports
  dynamic "rule" {
    for_each = var.allowed_inbound
    content {
      direction  = "in"
      port       = tostring(rule.value.port)
      protocol   = rule.value.protocol
      source_ips = rule.value.source_ips
    }
  }

  # SC-7: Allow all outbound by default (can be restricted via additional rules)
  rule {
    direction       = "out"
    port            = "1-65535"
    protocol        = "tcp"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction       = "out"
    port            = "1-65535"
    protocol        = "udp"
    destination_ips = ["0.0.0.0/0", "::/0"]
  }
}

# -- Optional: Attach firewall to specific servers ----------------------------

resource "hcloud_firewall_attachment" "servers" {
  count = length(var.server_ids) > 0 ? 1 : 0

  firewall_id = hcloud_firewall.main.id
  server_ids  = var.server_ids
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/hetzner-firewall"
  resource_id    = hcloud_firewall.main.id
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    inbound_rule_count = tostring(length(var.allowed_inbound))
    servers_attached   = tostring(length(var.server_ids))
  }
}
