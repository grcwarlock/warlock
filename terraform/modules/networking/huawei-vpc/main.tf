###############################################################################
# Huawei Cloud VPC Baseline
# Enforces: SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    huaweicloud = { source = "huaweicloud/huaweicloud", version = "~> 1.60" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-7: VPC with isolated network boundary --------------------------------

resource "huaweicloud_vpc" "main" {
  name = "${var.name_prefix}-vpc"
  cidr = var.vpc_cidr

  tags = local.common_tags
}

# -- SC-7: Subnets across multiple availability zones ------------------------

resource "huaweicloud_vpc_subnet" "main" {
  for_each = { for idx, cidr in var.subnet_cidrs : idx => {
    cidr    = cidr
    gateway = cidrhost(cidr, 1)
    zone    = var.availability_zones[idx % length(var.availability_zones)]
  } }

  name              = "${var.name_prefix}-subnet-${each.key}"
  vpc_id            = huaweicloud_vpc.main.id
  cidr              = each.value.cidr
  gateway_ip        = each.value.gateway
  availability_zone = each.value.zone

  tags = local.common_tags
}

# -- SC-7: Security group with deny-all default ------------------------------

resource "huaweicloud_networking_secgroup" "main" {
  name                 = "${var.name_prefix}-sg"
  description          = "Warlock-managed security group with deny-all default"
  delete_default_rules = true

  tags = local.common_tags
}

# -- SC-7: Specific allow rules (egress HTTPS only by default) ---------------

resource "huaweicloud_networking_secgroup_rule" "egress_https" {
  security_group_id = huaweicloud_networking_secgroup.main.id
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  description       = "Allow outbound HTTPS"
}

resource "huaweicloud_networking_secgroup_rule" "egress_dns_tcp" {
  security_group_id = huaweicloud_networking_secgroup.main.id
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  description       = "Allow outbound DNS over TCP"
}

resource "huaweicloud_networking_secgroup_rule" "egress_dns_udp" {
  security_group_id = huaweicloud_networking_secgroup.main.id
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  description       = "Allow outbound DNS over UDP"
}

# -- SC-7: NAT Gateway for private subnet internet access (optional) ---------

resource "huaweicloud_nat_gateway" "main" {
  count = var.enable_nat ? 1 : 0

  name      = "${var.name_prefix}-nat"
  vpc_id    = huaweicloud_vpc.main.id
  subnet_id = values(huaweicloud_vpc_subnet.main)[0].id
  spec      = "1"

  tags = local.common_tags
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/huawei-vpc"
  resource_id    = huaweicloud_vpc.main.id
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    vpc_cidr   = var.vpc_cidr
    enable_nat = tostring(var.enable_nat)
  }
}
