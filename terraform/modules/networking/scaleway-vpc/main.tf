###############################################################################
# Scaleway VPC + Security Group
# Enforces: SC-7 (Boundary Protection)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    scaleway = { source = "scaleway/scaleway", version = "~> 2.30" }
  }
}

# -- SC-7: VPC ----------------------------------------------------------------

resource "scaleway_vpc" "main" {
  name       = "${var.name_prefix}-vpc"
  region     = var.region
  project_id = var.project_id
  tags       = concat(var.tags, ["managed-by:warlock", "framework:nist-800-53"])
}

# -- SC-7: Private network within VPC ----------------------------------------

resource "scaleway_vpc_private_network" "main" {
  name       = "${var.name_prefix}-private-network"
  region     = var.region
  project_id = var.project_id
  vpc_id     = scaleway_vpc.main.id
  tags       = concat(var.tags, ["managed-by:warlock"])
}

# -- SC-7: Security group — deny all inbound by default ----------------------

resource "scaleway_instance_security_group" "main" {
  name                    = "${var.name_prefix}-sg"
  project_id              = var.project_id
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
  tags                    = concat(var.tags, ["managed-by:warlock"])

  dynamic "inbound_rule" {
    for_each = var.allowed_inbound_ports
    content {
      action   = "accept"
      port     = inbound_rule.value
      protocol = "TCP"
    }
  }
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "networking/scaleway-vpc"
  resource_id    = scaleway_vpc.main.id
  control_ids    = ["SC-7"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    region                 = var.region
    inbound_default_policy = "drop"
    allowed_ports          = join(",", [for p in var.allowed_inbound_ports : tostring(p)])
  }
}
