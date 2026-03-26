###############################################################################
# IBM Cloud VPC Networking Baseline
# Enforces: SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    ibm = { source = "IBM-Cloud/ibm", version = "~> 1.60" }
  }
}

locals {
  common_tags = concat(var.tags, ["managed-by:warlock"])
}

# -- SC-7: VPC ----------------------------------------------------------------

resource "ibm_is_vpc" "main" {
  name                      = "${var.name_prefix}-vpc"
  resource_group            = var.resource_group_id
  address_prefix_management = "manual"
  tags                      = local.common_tags
}

# -- SC-7: Address Prefixes ---------------------------------------------------

resource "ibm_is_vpc_address_prefix" "zones" {
  for_each = { for idx, zone in var.zones : zone => var.subnet_cidrs[idx] }

  name = "${var.name_prefix}-prefix-${each.key}"
  vpc  = ibm_is_vpc.main.id
  zone = each.key
  cidr = each.value
}

# -- SC-7: Subnets (one per zone) ---------------------------------------------

resource "ibm_is_subnet" "zones" {
  for_each = { for idx, zone in var.zones : zone => var.subnet_cidrs[idx] }

  name            = "${var.name_prefix}-subnet-${each.key}"
  vpc             = ibm_is_vpc.main.id
  zone            = each.key
  ipv4_cidr_block = each.value
  resource_group  = var.resource_group_id
  tags            = local.common_tags

  depends_on = [ibm_is_vpc_address_prefix.zones]
}

# -- SC-7: Security Group (deny-all default, explicit allows) -----------------

resource "ibm_is_security_group" "main" {
  name           = "${var.name_prefix}-sg"
  vpc            = ibm_is_vpc.main.id
  resource_group = var.resource_group_id
  tags           = local.common_tags
}

resource "ibm_is_security_group_rule" "inbound_vpc" {
  group     = ibm_is_security_group.main.id
  direction = "inbound"
  remote    = ibm_is_vpc.main.default_security_group

  tcp {
    port_min = 443
    port_max = 443
  }
}

resource "ibm_is_security_group_rule" "outbound_all" {
  group     = ibm_is_security_group.main.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# -- SC-7: Public Gateway (optional) ------------------------------------------

resource "ibm_is_public_gateway" "zones" {
  for_each = var.enable_public_gateway ? toset(var.zones) : toset([])

  name           = "${var.name_prefix}-pgw-${each.key}"
  vpc            = ibm_is_vpc.main.id
  zone           = each.key
  resource_group = var.resource_group_id
  tags           = local.common_tags
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/ibm-vpc"
  resource_id    = ibm_is_vpc.main.id
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    zones                 = join(",", var.zones)
    enable_public_gateway = tostring(var.enable_public_gateway)
  }
}
