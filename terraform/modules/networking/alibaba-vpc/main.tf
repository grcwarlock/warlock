###############################################################################
# Alibaba Cloud VPC Baseline
# Enforces: SC-7 (Boundary Protection), AU-2 (Audit Events)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    alicloud = { source = "aliyun/alicloud", version = "~> 1.220" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-7: VPC with isolated network boundary --------------------------------

resource "alicloud_vpc" "main" {
  vpc_name   = "${var.name_prefix}-vpc"
  cidr_block = var.vpc_cidr

  tags = local.common_tags
}

# -- SC-7: VSwitches across multiple availability zones ----------------------

resource "alicloud_vswitch" "main" {
  for_each = { for idx, cidr in var.vswitch_cidrs : idx => {
    cidr = cidr
    zone = var.availability_zones[idx % length(var.availability_zones)]
  } }

  vswitch_name = "${var.name_prefix}-vsw-${each.key}"
  vpc_id       = alicloud_vpc.main.id
  cidr_block   = each.value.cidr
  zone_id      = each.value.zone

  tags = local.common_tags
}

# -- SC-7: Security group with deny-all default ------------------------------

resource "alicloud_security_group" "main" {
  name   = "${var.name_prefix}-sg"
  vpc_id = alicloud_vpc.main.id

  tags = local.common_tags
}

# -- SC-7: Specific allow rules (egress HTTPS only by default) ---------------

resource "alicloud_security_group_rule" "egress_https" {
  type              = "egress"
  ip_protocol       = "tcp"
  port_range        = "443/443"
  security_group_id = alicloud_security_group.main.id
  cidr_ip           = "0.0.0.0/0"
  description       = "Allow outbound HTTPS"
}

resource "alicloud_security_group_rule" "egress_dns_tcp" {
  type              = "egress"
  ip_protocol       = "tcp"
  port_range        = "53/53"
  security_group_id = alicloud_security_group.main.id
  cidr_ip           = "0.0.0.0/0"
  description       = "Allow outbound DNS over TCP"
}

resource "alicloud_security_group_rule" "egress_dns_udp" {
  type              = "egress"
  ip_protocol       = "udp"
  port_range        = "53/53"
  security_group_id = alicloud_security_group.main.id
  cidr_ip           = "0.0.0.0/0"
  description       = "Allow outbound DNS over UDP"
}

# -- SC-7: NAT Gateway for private subnet internet access (optional) ---------

resource "alicloud_nat_gateway" "main" {
  count = var.enable_nat ? 1 : 0

  nat_gateway_name = "${var.name_prefix}-nat"
  vpc_id           = alicloud_vpc.main.id
  nat_type         = "Enhanced"
  vswitch_id       = values(alicloud_vswitch.main)[0].id
  payment_type     = "PayAsYouGo"

  tags = local.common_tags
}

resource "alicloud_eip_address" "nat" {
  count = var.enable_nat ? 1 : 0

  address_name = "${var.name_prefix}-nat-eip"
  payment_type = "PayAsYouGo"

  tags = local.common_tags
}

resource "alicloud_eip_association" "nat" {
  count = var.enable_nat ? 1 : 0

  allocation_id = alicloud_eip_address.nat[0].id
  instance_id   = alicloud_nat_gateway.main[0].id
  instance_type = "Nat"
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/alibaba-vpc"
  resource_id    = alicloud_vpc.main.id
  control_ids    = ["SC-7", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    vpc_cidr   = var.vpc_cidr
    enable_nat = tostring(var.enable_nat)
  }
}
