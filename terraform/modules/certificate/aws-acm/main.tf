###############################################################################
# AWS ACM Certificate Management Baseline
# Enforces: SC-17 (PKI Certificates), SC-23 (Session Authenticity)
###############################################################################

terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
}

# -- SC-17: ACM certificate with DNS validation --------------------------------

resource "aws_acm_certificate" "main" {
  domain_name               = var.domain_name
  subject_alternative_names = var.subject_alternative_names
  validation_method         = var.validation_method
  tags                      = merge(local.common_tags, { Name = "${var.name_prefix}-acm-cert" })

  lifecycle {
    create_before_destroy = true
  }
}

# -- SC-17: Certificate validation (optional, requires Route53 records) --------

resource "aws_acm_certificate_validation" "main" {
  count           = var.validate_certificate ? 1 : 0
  certificate_arn = aws_acm_certificate.main.arn
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "certificate/aws-acm"
  resource_id    = aws_acm_certificate.main.arn
  control_ids    = ["SC-17", "SC-23"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    domain_name       = var.domain_name
    validation_method = var.validation_method
  }
}
