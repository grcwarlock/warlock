###############################################################################
# Warlock Connector Provisioning — OT/ICS
# Network segmentation, firewall rules, and jump host configuration for
# OT/ICS connector access (Claroty, Dragos, Nozomi).
# Enforces: SC-7 (Boundary Protection), AC-4 (Information Flow Enforcement),
#           CA-3 (System Interconnections)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  common_tags = merge(var.tags, {
    managed_by = "warlock"
    component  = "connector-provisioning"
    vendor     = var.vendor
  })
  name_prefix = "${var.name_prefix}-ot-${var.vendor}"

  # Vendor-specific API port defaults
  vendor_ports = {
    claroty = { api_port = 443, protocol = "tcp" }
    dragos  = { api_port = 443, protocol = "tcp" }
    nozomi  = { api_port = 443, protocol = "tcp" }
  }
  api_port = coalesce(var.api_port, local.vendor_ports[var.vendor].api_port)
}

# -- Security Group for Warlock-to-OT traffic ---------------------------------

resource "aws_security_group" "warlock_ot_access" {
  name        = "${local.name_prefix}-access"
  description = "Allow Warlock to reach ${var.vendor} API on OT network (SC-7)"
  vpc_id      = var.vpc_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-access"
  })
}

# Egress: Warlock -> OT vendor API
resource "aws_vpc_security_group_egress_rule" "warlock_to_ot" {
  security_group_id = aws_security_group.warlock_ot_access.id

  description = "Allow Warlock to reach ${var.vendor} API"
  cidr_ipv4   = var.ot_network_cidr
  from_port   = local.api_port
  to_port     = local.api_port
  ip_protocol = "tcp"

  tags = local.common_tags
}

# -- Security Group for OT network allowing Warlock ingress -------------------

resource "aws_security_group" "ot_warlock_ingress" {
  name        = "${local.name_prefix}-ot-ingress"
  description = "Allow inbound from Warlock network to ${var.vendor} API (SC-7)"
  vpc_id      = var.vpc_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ot-ingress"
  })
}

# Ingress: Warlock network -> OT vendor API port
resource "aws_vpc_security_group_ingress_rule" "warlock_to_ot_api" {
  security_group_id = aws_security_group.ot_warlock_ingress.id

  description = "Allow Warlock network to reach ${var.vendor} API"
  cidr_ipv4   = var.warlock_network_cidr
  from_port   = local.api_port
  to_port     = local.api_port
  ip_protocol = "tcp"

  tags = local.common_tags
}

# -- Network ACL rules for defense in depth -----------------------------------

resource "aws_network_acl" "ot_boundary" {
  count = var.create_nacl ? 1 : 0

  vpc_id     = var.vpc_id
  subnet_ids = var.ot_subnet_ids

  # Allow inbound from Warlock on vendor API port only
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.warlock_network_cidr
    from_port  = local.api_port
    to_port    = local.api_port
  }

  # Allow ephemeral return traffic to Warlock
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.warlock_network_cidr
    from_port  = 1024
    to_port    = 65535
  }

  # Deny all other inbound from IT network
  ingress {
    rule_no    = 900
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow outbound responses to Warlock
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.warlock_network_cidr
    from_port  = 1024
    to_port    = 65535
  }

  # Deny all other outbound (data diode behavior)
  egress {
    rule_no    = 900
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-boundary-nacl"
  })
}

# -- VPC Flow Logs for OT boundary audit --------------------------------------

resource "aws_cloudwatch_log_group" "ot_flow_logs" {
  name              = "/warlock/${local.name_prefix}/vpc-flow-logs"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

resource "aws_iam_role" "flow_log" {
  name = "${local.name_prefix}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_log" {
  name = "${local.name_prefix}-flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "${aws_cloudwatch_log_group.ot_flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "ot_boundary" {
  vpc_id               = var.vpc_id
  traffic_type         = "ALL"
  log_destination      = aws_cloudwatch_log_group.ot_flow_logs.arn
  log_destination_type = "cloud-watch-logs"
  iam_role_arn         = aws_iam_role.flow_log.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-boundary-flow-log"
  })
}

# -- Warlock self-registration ------------------------------------------------

