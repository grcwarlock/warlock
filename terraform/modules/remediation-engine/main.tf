###############################################################################
# Warlock Remediation Engine
# Bridges Warlock API to Terraform Cloud — when a non-compliant resource is
# detected, invokes TFC to apply the appropriate remediation module.
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
    Component = "remediation-engine"
  })
  function_name = "${var.name_prefix}-remediation-engine"
}

# -- SSM SecureString for TFC token ------------------------------------------

resource "aws_ssm_parameter" "tfc_token" {
  name        = "/${var.name_prefix}/remediation-engine/tfc-token"
  description = "Terraform Cloud API token for Warlock remediation engine"
  type        = "SecureString"
  value       = var.tfc_token
  key_id      = var.kms_key_arn

  tags = local.common_tags
}

# -- SSM SecureString for Warlock API token ----------------------------------

resource "aws_ssm_parameter" "warlock_api_token" {
  name        = "/${var.name_prefix}/remediation-engine/warlock-api-token"
  description = "Warlock API bearer token for remediation engine self-registration"
  type        = "SecureString"
  value       = var.warlock_api_token
  key_id      = var.kms_key_arn

  tags = local.common_tags
}

# -- IAM role for Lambda -----------------------------------------------------

resource "aws_iam_role" "remediation_lambda" {
  name = "${local.function_name}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "remediation_lambda" {
  name = "${local.function_name}-policy"
  role = aws_iam_role.remediation_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.function_name}:*"
      },
      {
        Sid    = "ReadSSMParameters"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = [
          aws_ssm_parameter.tfc_token.arn,
          aws_ssm_parameter.warlock_api_token.arn,
        ]
      },
    ]
  })
}

# -- Lambda function (handler.py packaged as ZIP) ----------------------------

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.root}/.terraform/tmp/remediation-engine-handler.zip"
}

resource "aws_lambda_function" "remediation_engine" {
  function_name = local.function_name
  description   = "Warlock remediation engine: bridges API to Terraform Cloud for automated remediation"
  role          = aws_iam_role.remediation_lambda.arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  timeout       = var.lambda_timeout_seconds
  memory_size   = 256

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256

  environment {
    variables = {
      TFC_ORG              = var.tfc_org
      TFC_TOKEN_PARAM      = aws_ssm_parameter.tfc_token.name
      WARLOCK_API_ENDPOINT = var.warlock_api_endpoint != null ? var.warlock_api_endpoint : ""
      WARLOCK_TOKEN_PARAM  = aws_ssm_parameter.warlock_api_token.name
    }
  }

  # SC-28: encrypt Lambda environment variables at rest
  kms_key_arn = var.kms_key_arn

  tracing_config {
    mode = "Active"
  }

  tags = local.common_tags
}

# -- CloudWatch Logs for the Lambda ------------------------------------------

resource "aws_cloudwatch_log_group" "remediation_lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.common_tags
}

# -- Lambda Function URL (for Warlock API to invoke directly) ----------------

resource "aws_lambda_function_url" "remediation_engine" {
  function_name      = aws_lambda_function.remediation_engine.function_name
  authorization_type = "AWS_IAM"
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "remediation-engine"
  resource_id    = aws_lambda_function.remediation_engine.arn
  control_ids    = []
  remediation_id = var.warlock_remediation_id
  attributes = {
    function_name = local.function_name
    function_url  = aws_lambda_function_url.remediation_engine.function_url
    tfc_org       = var.tfc_org
  }
}
