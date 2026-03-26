###############################################################################
# Linode Cloud Firewall
# Enforces: SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    linode = { source = "linode/linode", version = "~> 2.12" }
  }
}

# -- SC-7: Firewall with deny-all inbound default ----------------------------

resource "linode_firewall" "main" {
  label           = "${var.name_prefix}-firewall"
  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"
  tags            = var.tags

  dynamic "inbound" {
    for_each = var.allowed_inbound
    content {
      label    = inbound.value.label
      action   = "ACCEPT"
      protocol = inbound.value.protocol
      ports    = inbound.value.ports
      ipv4     = inbound.value.ipv4_addresses
      ipv6     = lookup(inbound.value, "ipv6_addresses", [])
    }
  }

  linodes = var.linode_ids
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/linode-firewall"
  resource_id    = tostring(linode_firewall.main.id)
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    inbound_policy      = "DROP"
    outbound_policy     = "ACCEPT"
    inbound_rules_count = tostring(length(var.allowed_inbound))
    attached_linodes    = tostring(length(var.linode_ids))
  }
}
