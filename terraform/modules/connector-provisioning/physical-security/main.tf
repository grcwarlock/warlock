###############################################################################
# Warlock Connector Provisioning — Physical Security
# Network access, API credential storage, and endpoint configuration for
# physical security connectors (Lenel, Genetec, HID).
# Enforces: PE-3 (Physical Access Control), PE-6 (Monitoring Physical Access),
#           SC-12 (Cryptographic Key Management)
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
  name_prefix = "${var.name_prefix}-physec-${var.vendor}"

  # Vendor-specific defaults
  vendor_config = {
    lenel = {
      default_port = 443
      protocol     = "https"
      description  = "Lenel OnGuard access control system"
    }
    genetec = {
      default_port = 443
      protocol     = "https"
      description  = "Genetec Security Center"
    }
    hid = {
      default_port = 443
      protocol     = "https"
      description  = "HID Global access control system"
    }
  }
  api_port = coalesce(var.api_port, local.vendor_config[var.vendor].default_port)
}

# -- Security Group for Warlock-to-Panel access -------------------------------

resource "aws_security_group" "warlock_panel_access" {
  name        = "${local.name_prefix}-access"
  description = "Allow Warlock to reach ${var.vendor} panel at ${var.panel_endpoint} (PE-3)"
  vpc_id      = var.vpc_id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-access"
  })
}

resource "aws_vpc_security_group_egress_rule" "to_panel" {
  security_group_id = aws_security_group.warlock_panel_access.id

  description = "Allow Warlock to reach ${var.vendor} panel API"
  cidr_ipv4   = "${var.panel_endpoint}/32"
  from_port   = local.api_port
  to_port     = local.api_port
  ip_protocol = "tcp"

  tags = local.common_tags
}

# -- API credential storage ---------------------------------------------------

# Store credentials in AWS Secrets Manager
resource "aws_secretsmanager_secret" "panel_credentials" {
  count = var.secret_backend == "aws_sm" ? 1 : 0

  name        = "${var.name_prefix}/physical-security/${var.vendor}/credentials"
  description = "API credentials for ${local.vendor_config[var.vendor].description}"
  kms_key_id  = var.kms_key_arn

  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "panel_credentials" {
  count = var.secret_backend == "aws_sm" && length(var.panel_credentials) > 0 ? 1 : 0

  secret_id = aws_secretsmanager_secret.panel_credentials[0].id
  secret_string = jsonencode(merge(var.panel_credentials, {
    endpoint = "https://${var.panel_endpoint}:${local.api_port}"
    vendor   = var.vendor
  }))
}

# Store credentials in SSM (lightweight alternative)
resource "aws_ssm_parameter" "panel_api_key" {
  count = var.secret_backend == "ssm" ? 1 : 0

  name        = "/${var.name_prefix}/physical-security/${var.vendor}/api-key"
  description = "API key for ${local.vendor_config[var.vendor].description}"
  type        = "SecureString"
  value       = lookup(var.panel_credentials, "api_key", "PLACEHOLDER")
  key_id      = var.kms_key_arn

  tags = local.common_tags
}

# -- Badge system integration endpoint config ---------------------------------

resource "aws_ssm_parameter" "panel_endpoint" {
  name        = "/${var.name_prefix}/physical-security/${var.vendor}/endpoint"
  description = "API endpoint for ${local.vendor_config[var.vendor].description}"
  type        = "String"
  value = jsonencode({
    host     = var.panel_endpoint
    port     = local.api_port
    protocol = local.vendor_config[var.vendor].protocol
    vendor   = var.vendor
    url      = "${local.vendor_config[var.vendor].protocol}://${var.panel_endpoint}:${local.api_port}"
  })

  tags = local.common_tags
}

# -- CloudWatch log group for physical security audit -------------------------

resource "aws_cloudwatch_log_group" "physec_audit" {
  name              = "/warlock/${local.name_prefix}/audit"
  retention_in_days = var.log_retention_days

  tags = local.common_tags
}

# -- Warlock self-registration ------------------------------------------------

