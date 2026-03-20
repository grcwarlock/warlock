###############################################################################
# Warlock Drift Detector
# Reads Terraform state from S3, compares against AWS Config, publishes to SNS
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
    ManagedBy = "warlock"
    Framework = "NIST-800-53"
  })
  function_name = "${var.name_prefix}-drift-detector"
}

# ── SNS topic for drift findings ──────────────────────────────────────

resource "aws_sns_topic" "drift_findings" {
  name              = "${var.name_prefix}-drift-findings"
  kms_master_key_id = var.kms_key_arn
  tags              = local.common_tags
}

resource "aws_sns_topic_subscription" "drift_email" {
  count     = length(var.alert_emails)
  topic_arn = aws_sns_topic.drift_findings.arn
  protocol  = "email"
  endpoint  = var.alert_emails[count.index]
}

# ── IAM role for Lambda ───────────────────────────────────────────────

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

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.drift_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "drift_lambda" {
  name = "${local.function_name}-policy"
  role = aws_iam_role.drift_lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read Terraform state from S3
        Sid    = "ReadTerraformState"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          var.state_bucket_arn,
          "${var.state_bucket_arn}/*",
        ]
      },
      {
        # Query AWS Config for live resource configuration
        Sid    = "ReadAWSConfig"
        Effect = "Allow"
        Action = [
          "config:GetResourceConfigHistory",
          "config:DescribeConfigRules",
          "config:DescribeComplianceByResource",
          "config:ListDiscoveredResources",
        ]
        Resource = "*"
      },
      {
        # Publish findings to SNS
        Sid      = "PublishDriftFindings"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.drift_findings.arn
      },
      {
        # Decrypt state file if bucket uses KMS
        Sid    = "DecryptState"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey",
        ]
        Resource = var.kms_key_arn != null ? [var.kms_key_arn] : ["*"]
        Condition = var.kms_key_arn != null ? {} : {
          StringEquals = { "kms:CallerAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        # #13: Read API token from SSM Parameter Store
        Sid    = "ReadSSMToken"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        Resource = var.warlock_api_token != null ? [
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.name_prefix}/drift-detector/warlock-api-token"
        ] : []
      },
      {
        # CloudWatch Logs for Lambda
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.function_name}:*"
      },
    ]
  })
}

# ── Lambda function (handler.py packaged as ZIP) ──────────────────────

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda/handler.py"
  output_path = "${path.root}/.terraform/tmp/drift-detector-handler.zip"
}

resource "aws_lambda_function" "drift_detector" {
  function_name = local.function_name
  description   = "Warlock drift detection: compares Terraform state against live AWS Config. CM-3, CM-8"
  role          = aws_iam_role.drift_lambda.arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  timeout       = var.lambda_timeout_seconds
  memory_size   = 256

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256

  environment {
    variables = {
      TF_STATE_BUCKET      = var.state_bucket_name
      TF_STATE_KEY         = var.state_key
      SNS_TOPIC_ARN        = aws_sns_topic.drift_findings.arn
      WARLOCK_API_ENDPOINT = var.warlock_api_endpoint != null ? var.warlock_api_endpoint : ""
      # #13: Token moved to SSM SecureString — Lambda reads it at runtime via SSM API
      WARLOCK_API_TOKEN_SSM_PARAM = var.warlock_api_token != null ? aws_ssm_parameter.api_token[0].name : ""
    }
  }

  # SC-28: encrypt Lambda environment variables at rest
  kms_key_arn = var.kms_key_arn

  tracing_config {
    mode = "Active" # X-Ray tracing for observability
  }

  tags = local.common_tags
}

# ── CloudWatch Logs for the Lambda ───────────────────────────────────

resource "aws_cloudwatch_log_group" "drift_lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.common_tags
}

# ── EventBridge scheduled trigger ─────────────────────────────────────

resource "aws_cloudwatch_event_rule" "drift_schedule" {
  name                = "${local.function_name}-schedule"
  description         = "Trigger Warlock drift detection on schedule (CM-3)"
  schedule_expression = var.schedule_expression
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "drift_lambda" {
  rule      = aws_cloudwatch_event_rule.drift_schedule.name
  target_id = "drift-detector-lambda"
  arn       = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.drift_schedule.arn
}

# ── #13: SSM SecureString for API token ─────────────────────────────
# Stores the Warlock API token in SSM Parameter Store as a SecureString
# instead of as a plaintext Lambda environment variable.

resource "aws_ssm_parameter" "api_token" {
  count       = var.warlock_api_token != null ? 1 : 0
  name        = "/${var.name_prefix}/drift-detector/warlock-api-token"
  description = "Warlock API bearer token for drift detector self-registration"
  type        = "SecureString"
  value       = var.warlock_api_token
  key_id      = var.kms_key_arn

  tags = local.common_tags
}

# ── #41: Warlock self-registration evidence ───────────────────────────

variable "warlock_api_endpoint" {
  description = "Warlock API base URL for self-registration evidence. Set to null to disable."
  type        = string
  default     = null
}

variable "warlock_api_token" {
  description = "Bearer token for Warlock API authentication."
  type        = string
  default     = null
  sensitive   = true
}

resource "terraform_data" "warlock_evidence" {
  count = var.warlock_api_endpoint != null ? 1 : 0

  triggers_replace = [aws_lambda_function.drift_detector.arn]

  provisioner "local-exec" {
    environment = {
      WARLOCK_API_ENDPOINT = var.warlock_api_endpoint
      WARLOCK_API_TOKEN    = var.warlock_api_token
    }
    command = <<-EOT
      curl -sf -X POST "$WARLOCK_API_ENDPOINT/api/v1/evidence" \
        -H "Authorization: Bearer $WARLOCK_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
          "module": "aws/drift-detector",
          "resource_id": "${aws_lambda_function.drift_detector.arn}",
          "control_ids": ["CM-3", "CM-8"],
          "attributes": {
            "function_name": "${local.function_name}",
            "schedule": "${var.schedule_expression}",
            "state_bucket": "${var.state_bucket_name}",
            "state_key": "${var.state_key}"
          }
        }' || true
    EOT
  }
}
