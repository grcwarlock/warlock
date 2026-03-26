###############################################################################
# Huawei Cloud ECS Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Settings)
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

# -- CM-6: Security group for the ECS instance -------------------------------

resource "huaweicloud_networking_secgroup" "instance" {
  name                 = "${var.name_prefix}-ecs-sg"
  description          = "Warlock-managed security group for ECS instance"
  delete_default_rules = true

  tags = local.common_tags
}

# -- CM-6: Allow only HTTPS egress by default --------------------------------

resource "huaweicloud_networking_secgroup_rule" "egress_https" {
  security_group_id = huaweicloud_networking_secgroup.instance.id
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  description       = "Allow outbound HTTPS"
}

# -- SC-28/CM-6: ECS instance with encrypted disks --------------------------

resource "huaweicloud_compute_instance" "main" {
  name              = "${var.name_prefix}-ecs"
  image_id          = var.image_id
  flavor_id         = var.flavor_id
  availability_zone = var.availability_zone

  network {
    uuid = var.subnet_id
  }

  security_group_ids = [
    var.security_group_id != null ? var.security_group_id : huaweicloud_networking_secgroup.instance.id
  ]

  system_disk_type = "SAS"
  system_disk_size = 40

  data_disks {
    type       = "SAS"
    size       = 100
    kms_key_id = var.kms_key_id
  }

  tags = local.common_tags
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/huawei-ecs"
  resource_id    = huaweicloud_compute_instance.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    flavor_id      = var.flavor_id
    disk_encrypted = var.kms_key_id != null ? "true" : "false"
  }
}
