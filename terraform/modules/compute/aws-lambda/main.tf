###############################################################################
# AWS Lambda Hardening
# Enforces: SC-7 (VPC Placement), SC-28 (Env Var Encryption), AU-2 (Logging)
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
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })

  # SC-7: VPC config only when subnets are provided
  vpc_config = length(var.subnet_ids) > 0 ? [{
    subnet_ids         = var.subnet_ids
    security_group_ids = var.security_group_ids
  }] : []
}

# -- AU-2: CloudWatch log group for Lambda ------------------------------------

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name_prefix}-${var.function_name}"
  retention_in_days = 90
  kms_key_id        = var.kms_key_arn

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-${var.function_name}-logs" })
}

# -- SC-7, SC-28, AU-2: Hardened Lambda function ------------------------------

resource "aws_lambda_function" "main" {
  function_name = "${var.name_prefix}-${var.function_name}"
  runtime       = var.runtime
  handler       = var.handler
  filename      = var.filename
  role          = var.role_arn

  # SC-28: Encrypt environment variables at rest with KMS
  kms_key_arn = var.kms_key_arn

  # AU-2: Active X-Ray tracing
  tracing_config {
    mode = "Active"
  }

  # SC-7: VPC placement when subnets are provided
  dynamic "vpc_config" {
    for_each = local.vpc_config
    content {
      subnet_ids         = vpc_config.value.subnet_ids
      security_group_ids = vpc_config.value.security_group_ids
    }
  }

  dynamic "environment" {
    for_each = length(var.environment_variables) > 0 ? [1] : []
    content {
      variables = var.environment_variables
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]

  tags = merge(local.common_tags, { Name = "${var.name_prefix}-${var.function_name}" })
}

# -- Warlock closed-loop registration -----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "compute/aws-lambda"
  resource_id    = aws_lambda_function.main.arn
  control_ids    = ["SC-7", "SC-28", "AU-2"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    xray_tracing  = "Active"
    vpc_enabled   = tostring(length(var.subnet_ids) > 0)
    kms_encrypted = tostring(var.kms_key_arn != null)
  }
}
