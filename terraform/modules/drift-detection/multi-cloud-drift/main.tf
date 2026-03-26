###############################################################################
# Warlock Multi-Cloud Drift Detector
# Reads Terraform state files from S3, analyzes for drift indicators,
# and reports findings to the Warlock API as evidence.
# Enforces: CM-3 (Configuration Change Control), CM-8 (Component Inventory)
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
    ManagedBy   = "warlock"
    Framework   = "NIST-800-53"
    environment = lookup(var.tags, "environment", "unknown")
    team        = lookup(var.tags, "team", "platform")
    managed-by  = "terraform"
  })
  function_name = "${var.name_prefix}-multi-cloud-drift"
}

# -- IAM role for Lambda -----------------------------------------------------

resource "aws_iam_role" "drift_lambda" {
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

resource "aws_iam_role_policy" "drift_lambda" {
  name = "${local.function_name}-policy"
  role = aws_iam_role.drift_lambda.id
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
        Sid    = "ReadTerraformState"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          var.state_bucket_arn,
          "${var.state_bucket_arn}/*",
        ]
      },
      {
        Sid    = "ReadSSMToken"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = [
          aws_ssm_parameter.api_token.arn,
        ]
      },
      {
        Sid    = "DecryptState"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = var.kms_key_arn != null ? [var.kms_key_arn] : []
      },
    ]
  })
}

# -- Lambda function (handler.py packaged as ZIP) ----------------------------

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.root}/.terraform/tmp/multi-cloud-drift-handler.zip"
}

resource "aws_lambda_function" "drift_detector" {
  function_name = local.function_name
  description   = "Warlock multi-cloud drift detection: analyzes Terraform state files for drift indicators. CM-3, CM-8"
  role          = aws_iam_role.drift_lambda.arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  timeout       = var.lambda_timeout_seconds
  memory_size   = 256

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256

  environment {
    variables = {
      STATE_BUCKET         = var.state_bucket_name
      STATE_KEYS           = jsonencode(var.state_keys)
      WARLOCK_API_ENDPOINT = var.warlock_api_endpoint != null ? var.warlock_api_endpoint : ""
      WARLOCK_TOKEN_PARAM  = aws_ssm_parameter.api_token.name
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

resource "aws_cloudwatch_log_group" "drift_lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.common_tags
}

# -- SSM SecureString for API token ------------------------------------------

resource "aws_ssm_parameter" "api_token" {
  name        = "/${var.name_prefix}/multi-cloud-drift/warlock-api-token"
  description = "Warlock API bearer token for multi-cloud drift detector"
  type        = "SecureString"
  value       = var.warlock_api_token
  key_id      = var.kms_key_arn

  tags = local.common_tags
}

# -- EventBridge scheduled trigger -------------------------------------------

resource "aws_cloudwatch_event_rule" "drift_schedule" {
  name                = "${local.function_name}-schedule"
  description         = "Trigger Warlock multi-cloud drift detection on schedule (CM-3)"
  schedule_expression = var.schedule_expression
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "drift_lambda" {
  rule      = aws_cloudwatch_event_rule.drift_schedule.name
  target_id = "multi-cloud-drift-lambda"
  arn       = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.drift_schedule.arn
}

# -- Warlock closed-loop registration ----------------------------------------

module "warlock_registration" {
  source = "../../_shared/warlock-registration"

  enabled        = var.warlock_api_endpoint != null
  api_endpoint   = coalesce(var.warlock_api_endpoint, "")
  api_token      = coalesce(var.warlock_api_token, "")
  module_name    = "drift-detection/multi-cloud-drift"
  resource_id    = aws_lambda_function.drift_detector.arn
  control_ids    = ["CM-3", "CM-8"]
  remediation_id = var.warlock_remediation_id
  attributes = {
    function_name = local.function_name
    schedule      = var.schedule_expression
    state_bucket  = var.state_bucket_name
    state_keys    = jsonencode(var.state_keys)
  }
}
