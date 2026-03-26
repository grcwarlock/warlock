###############################################################################
# IBM Cloud Virtual Server Instance Baseline
# Enforces: SC-28 (Encryption at Rest), CM-6 (Configuration Settings)
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

# -- SC-28/CM-6: Security Group for VSI ---------------------------------------

resource "ibm_is_security_group" "vsi" {
  name           = "${var.name_prefix}-vsi-sg"
  vpc            = var.vpc_id
  resource_group = var.resource_group_id
  tags           = local.common_tags
}

resource "ibm_is_security_group_rule" "inbound_ssh" {
  group     = ibm_is_security_group.vsi.id
  direction = "inbound"
  remote    = var.vpc_id

  tcp {
    port_min = 22
    port_max = 22
  }
}

resource "ibm_is_security_group_rule" "outbound_all" {
  group     = ibm_is_security_group.vsi.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# -- SC-28/CM-6: Virtual Server Instance --------------------------------------

resource "ibm_is_instance" "main" {
  name           = "${var.name_prefix}-vsi"
  vpc            = var.vpc_id
  zone           = var.zone
  profile        = var.profile
  image          = var.image_id
  resource_group = var.resource_group_id
  tags           = local.common_tags

  keys = var.ssh_key_ids

  primary_network_interface {
    subnet          = var.subnet_id
    security_groups = [ibm_is_security_group.vsi.id]
  }

  boot_volume {
    name       = "${var.name_prefix}-boot"
    encryption = var.boot_volume_encryption_key
  }

  metadata_service {
    enabled  = true
    protocol = "https"
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/ibm-vsi"
  resource_id    = ibm_is_instance.main.id
  control_ids    = ["SC-28", "CM-6"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    profile          = var.profile
    metadata_service = "enabled"
    boot_encrypted   = tostring(var.boot_volume_encryption_key != null)
  }
}
