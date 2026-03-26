###############################################################################
# OVH vRack Private Networking
# Enforces: SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    ovh = { source = "ovh/ovh", version = "~> 0.40" }
  }
}

locals {
  common_tags = {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  }
}

# -- SC-7: Attach cloud project to vRack for network isolation ----------------

resource "ovh_vrack_cloudproject" "attach" {
  service_name = var.vrack_id
  project_id   = var.service_name
}

# -- SC-7: Private network within the vRack -----------------------------------

resource "ovh_cloud_project_network_private" "main" {
  service_name = var.service_name
  name         = "${var.name_prefix}-private-network"
  regions      = [var.region]
  vlan_id      = var.vlan_id

  depends_on = [ovh_vrack_cloudproject.attach]
}

# -- SC-7: Subnet within the private network ----------------------------------

resource "ovh_cloud_project_network_private_subnet" "main" {
  service_name = var.service_name
  network_id   = ovh_cloud_project_network_private.main.id
  region       = var.region
  start        = cidrhost(var.subnet_cidr, 2)
  end          = cidrhost(var.subnet_cidr, 254)
  network      = var.subnet_cidr
  dhcp         = true
  no_gateway   = false
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/ovh-vrack"
  resource_id    = ovh_cloud_project_network_private.main.id
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    vrack_id    = var.vrack_id
    region      = var.region
    subnet_cidr = var.subnet_cidr
  }
}
