###############################################################################
# Alibaba Cloud ECS Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Settings)
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

# -- CM-6: Security group for the ECS instance -------------------------------

resource "alicloud_security_group" "instance" {
  name   = "${var.name_prefix}-ecs-sg"
  vpc_id = var.vpc_id

  tags = local.common_tags
}

# -- CM-6: Deny all ingress by default, allow only HTTPS egress -------------

resource "alicloud_security_group_rule" "egress_https" {
  type              = "egress"
  ip_protocol       = "tcp"
  port_range        = "443/443"
  security_group_id = alicloud_security_group.instance.id
  cidr_ip           = "0.0.0.0/0"
  description       = "Allow outbound HTTPS"
}

# -- SC-28/CM-6: ECS instance with encrypted disk and security hardening -----

resource "alicloud_instance" "main" {
  instance_name = "${var.name_prefix}-ecs"
  image_id      = var.image_id
  instance_type = var.instance_type
  vswitch_id    = var.vswitch_id

  security_groups = [
    var.security_group_id != null ? var.security_group_id : alicloud_security_group.instance.id
  ]

  system_disk_category  = "cloud_essd"
  system_disk_size      = 40
  system_disk_encrypted = true

  security_enhancement_strategy = "Active"

  internet_max_bandwidth_out = 0

  tags = local.common_tags
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/alibaba-ecs"
  resource_id    = alicloud_instance.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    instance_type     = var.instance_type
    disk_encrypted    = "true"
    security_strategy = "Active"
  }
}
